import logging
logging.basicConfig(level=logging.INFO)

import os
import requests
import io
import uuid
from datetime import datetime, timezone, timedelta
import pytz

import json
from dotenv import load_dotenv
load_dotenv()

# Google Cloud Datastore
from google.cloud import datastore, secretmanager
ds_client = datastore.Client(project="pickybook")

# Google Cloud Bucket
# Create the storage client with the correct project and credentials
from google.cloud import storage
from google.oauth2 import service_account
client = secretmanager.SecretManagerServiceClient()
secret_name = os.environ["STORAGE_ADMIN_CREDENTIALS"]
response = client.access_secret_version(request={"name": secret_name})
cred_dict = json.loads(response.payload.data.decode("UTF-8"))
storage_credentials = service_account.Credentials.from_service_account_info(cred_dict)
storage_client = storage.Client(project='pickybook', credentials=storage_credentials)
BUCKET_NAME = 'pickybook-bucket'

# Firebase Authentication
import firebase_admin
from firebase_admin import auth as firebase_auth, credentials
client = secretmanager.SecretManagerServiceClient()
secret_name = os.environ["FIREBASE_ADMIN_CREDENTIALS"]
response = client.access_secret_version(request={"name": secret_name})
secret_payload = response.payload.data.decode("UTF-8")
cred_dict = json.loads(secret_payload)
cred = credentials.Certificate(cred_dict)
firebase_admin.initialize_app(cred)

#print("Admin SDK project ID:", cred_dict.get("project_id"))
#print("Storage client project:", storage_client.project)
# OpenAI
from openai import OpenAI
openai_client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

from flask import Flask, render_template, redirect, url_for, request, jsonify, session, flash
app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY")


@app.route('/')
def index():
    # Calculate user age and default typical reading level
    current_date = datetime.now(timezone.utc).date()
    user_profile = session.get('user_profile')
    user_age = None
    reading_level = None
    if user_profile and user_profile.get('birthdate'):
        birthdate = datetime.strptime(user_profile['birthdate'], "%Y-%m-%d").date()
        user_age = current_date.year - birthdate.year - (
            (current_date.month, current_date.day) < (birthdate.month, birthdate.day)
        )
        
        reading_level = user_profile.get('reading_level')
        if not reading_level and user_age:
            reading_level = get_typical_grade_for_age(user_age)

    story_id = session.get('story_id')
    user = session.get('user')
    anon_id = session.get('anon_id')
    if story_id:
        story_set = get_story(story_id, user, anon_id)
    else:
        story_set = {}

    # Display create story page by default
    if not any([
        session.get('show_login_form'),
        session.get('show_stories'),
        session.get('show_create'),
        session.get('show_account'),
        session.get('story_id')
    ]):
        session['show_create'] = True

    scroll_on_load = request.args.get('scroll') == 'end'

    return render_template('index.html', 
                            show_login=session.get('show_login_form'),
                            show_stories=session.get('show_stories'),
                            show_create=session.get('show_create'),
                            show_account=session.get('show_account'),
                            user=session.get('user'), 
                            story_set=story_set,
                            user_profile=session.get('user_profile'),
                            user_details=session.get('user_details'),
                            show_create_account=session.get('show_create_account'),
                            scroll_on_load=scroll_on_load,
                            user_age=user_age,
                            reading_level=reading_level
                            )

def get_user_id():
    auth_header = request.headers.get('Authorization')
    if not auth_header:
        return None, (jsonify({"error": "Missing Authorization header"}), 401)
    if auth_header.startswith('Bearer '):
        id_token = auth_header.split('Bearer ')[1]
    else:
        id_token = auth_header.strip()
    try:
        decoded_token = firebase_auth.verify_id_token(id_token)
        uid = decoded_token['uid']
        return uid, None
    except Exception as e:
        logging.error(f"Token verification failed: {e}")
        return None, (jsonify({"error": "Invalid or expired token"}), 401)


def get_typical_grade_for_age(age):
    # Simple age-to-grade map
    if age < 5:
        return 'k'
    elif age == 5:
        return 'k'
    elif age == 6:
        return '1'
    elif age == 7:
        return '2'
    elif age == 8:
        return '3'
    elif age == 9:
        return '4'
    elif age == 10:
        return '5'
    elif age == 11:
        return '6'
    elif age == 12:
        return '7'
    elif age == 13:
        return '8'
    elif age == 14:
        return '9'
    else:
        return '12'


@app.route('/show_login', methods=['GET'])
def show_login():
    session['show_login_form'] = True
    session['show_create_account'] = False
    session['show_stories'] = False
    session['show_create'] = False
    session['show_account'] = False
    session['hold_story_id'] = session.get('story_id')
    session.pop('story_id', None)
    return redirect(url_for('index'))


@app.route('/hide_login', methods=['GET'])
def hide_login():
    session['show_login_form'] = False
    if session.get('hold_story_id'):
        session['show_create'] = False
        session['show_stories'] = False
        session['show_account'] = False
        session['story_id'] = session.get('hold_story_id')
        session.pop('hold_story_id')
    else:
        session['show_create'] = True
    return redirect(url_for('index'))


@app.route('/show_create_story_page', methods=['GET'])
def show_create_story_page():
    session['show_stories'] = False
    session['show_create_account'] = False
    session['show_account'] = False
    session['show_create'] = True
    session.pop('story_id', None)
    return redirect(url_for('index'))


@app.route('/api/v1/my_stories', methods=['GET'])
def my_stories_api():
    user, error = get_user_id()
    if error:
        return error
    user_stories = get_all_stories_for_user(user)
    for story in user_stories:
        story['created_at'] = to_localtime(story['created_at'])
        story['last_modified'] = to_localtime(story['last_modified'])
    return jsonify(user_stories)


@app.route('/my_stories', methods=['GET'])
def my_stories_web():
    user = session.get('user')
    session['show_stories'] = True
    session['show_create'] = False
    session['show_account'] = False
    session.pop('story_id', None)
    user_stories = get_all_stories_for_user(user)

    for story in user_stories:
        story['created_at'] = to_localtime(story['created_at'])
        story['last_modified'] = to_localtime(story['last_modified'])
    return render_template('index.html', 
                            show_stories=session.get('show_stories'),
                            show_create=session.get('show_create'),
                            show_account=session.get('show_account'),
                            user=session.get('user'), 
                            user_stories=user_stories,
                            user_profile=session.get('user_profile')
                            )


def to_localtime(utc_dt):
    if utc_dt is None:
        return ''
    user_tz = session.get('timezone', 'UTC')
    local_tz = pytz.timezone(user_tz)
    if utc_dt.tzinfo is None:
        utc_dt = utc_dt.replace(tzinfo=pytz.UTC)
    return utc_dt.astimezone(local_tz)


@app.route('/set_timezone', methods=['POST'])
def set_timezone():
    data = request.get_json()
    timezone = data.get('timezone')

    if timezone:
        session['timezone'] = timezone
        print('TIMEZONE SET:', session['timezone'])
        return ('', 204)
    else:
        print("Invalid timezone data")
        return ('Invalid timezone', 400)


@app.route('/api/v1/read_story/<int:story_id>', methods=['GET'])
def read_story_api(story_id):
    user = request.headers.get('Authorization')
    story_set = get_story(story_id, user, anon_id=None)
    if story_set:
        return jsonify(story_set)
    return jsonify({"error": "Story not found"}), 404


@app.route('/read_story/<int:story_id>', methods=['GET'])
def read_story_web(story_id):
    session['story_id'] = story_id
    session['show_stories'] = False
    session['show_create'] = False
    session['show_account'] = False
    return redirect(url_for('index', scroll='end'))


@app.route('/api/v1/account_settings', methods=['GET'])
def account_settings_api():
    user, error = get_user_id()
    if error:
        return error
    user_profile = get_user_profile(user)
    return jsonify(user_profile)


@app.route('/account_settings', methods=['GET'])
def account_settings_web():
    session['show_stories'] = False
    session['show_create'] = False
    session['show_account'] = True
    session.pop('story_id', None)
    user = session.get('user')
    user_profile = get_user_profile(user)
    session['user_profile'] = user_profile
    return redirect(url_for('index'))


def get_user_profile(user):
    if user:
        try:
            key = ds_client.key('UserProfile', user)
            profile_entity = ds_client.get(key) or {}
            user_profile = {
                'name': profile_entity.get('name', ''),
                'birthdate': profile_entity.get('birthdate', ''),
                'reading_level': profile_entity.get('reading_level', '')
            }
            return user_profile
        except Exception as e:
            print(f"Error getting user profile: {e}")
    return {}


@app.route('/show_create_account', methods=['GET'])
def show_create_account():
    session['show_create_account'] = True
    session['show_login_form'] = True
    return redirect(url_for('index'))


@app.route('/hide_create_account', methods=['GET'])
def hide_create_account():
    session['show_login_form'] = True
    session['show_create_account'] = False
    return redirect(url_for('index'))


@app.route('/api/v1/delete_account', methods=['POST'])
def delete_account_api():
    user, error = get_user_id()
    if error:
        return error
    success = delete_account(user)
    if success:
        return '', 204
    return jsonify({"error": "Failed to delete account. Please try again later."}), 500


@app.route('/delete_account', methods=['POST'])
def delete_account_web():
    user = session.get('user')
    success = delete_account(user)
    if not success:
        flash('Error deleting user account. Please try again later.')
    else:
        flash('Account deleted')
        # Clear session and redirect to home
        session.clear()
    return redirect(url_for('index'))


def delete_account(user):
    # Delete Firebase user
    try:
        firebase_auth.delete_user(user)
        # Delete all stories for user
        query = ds_client.query(kind='Story')
        query.add_filter('user', '=', user)
        keys = [entity.key for entity in query.fetch()]
        if keys:
            ds_client.delete_multi(keys)
        # Delete the user's profile entry
        profile_key = ds_client.key('UserProfile', user)
        ds_client.delete(profile_key)

        return True
    except Exception as e:
        print(f"Error deleting Firebase user: {e}")
        return False


@app.route('/api/v1/update_account/<int:user>', methods=['POST'])
def update_account_api(user):
    user, error = get_user_id()
    if error:
        return error
    data = request.get_json()
    if not data:
        return jsonify({"error": "Missing JSON body"}), 400
    user_profile = update_account(user, data)
    if user_profile:
        return jsonify(user_profile), 200
    return jsonify({"error": "Could not update profile. Please try again later."}), 500


@app.route('/update_account', methods=['POST'])
def update_account_web():
    user = session.get('user')
    user_profile = update_account(user)
    if user_profile:
        session['user_profile'] = user_profile
        flash('Profile updated!')
    else:
        flash('Could not update profile. Please try again later.')
    return redirect(url_for('account_settings_web'))


def update_account(user, form_data):
    # Fetch or create the UserProfile entity
    key = ds_client.key('UserProfile', user)
    profile = ds_client.get(key) or datastore.Entity(key=key)
    # Update fields from form
    profile['name'] = form_data.get('name', '').strip()
    profile['birthdate'] = form_data.get('birthdate', '').strip()
    profile['reading_level'] = form_data.get('reading_level', '').strip()
    try:
        ds_client.put(profile)
        user_profile = {
        'name': profile['name'],
        'birthdate': profile['birthdate'],
        'reading_level': profile['reading_level']
        }
        return user_profile
    except Exception as e:
        logging.error(f"Datastore put failed: {e}")
        return False


@app.route('/api/v1/session_login', methods=['POST'])
def session_login_api():
    data = request.get_json()
    if not data:
        return jsonify({"error": "Missing JSON body"}), 400
    id_token = data.get('idToken')
    if not id_token:
        return jsonify({"error": "Missing idToken"}), 400
    
    anon_id = data.get('anon_id')
    response = session_login(data, anon_id)
    user_info = response.get('user_info')
    error_msg = response.get('error_msg')
    if user_info:
        return jsonify(user_info), 200
    return jsonify({"error": error_msg}), 401


@app.route('/session_login', methods=['POST'])
def session_login_web():
    data = request.get_json()
    anon_id = session.get('anon_id')
    response = session_login(data, anon_id)
    error_msg = response.get('error_msg')
    user_info = response.get('user_info')
    if user_info:
        session['user_details'] = user_info
        session['user'] = user_info['uid']
        user = session.get('user')
        session['user_profile'] = get_user_profile(user)
        print('LOGIN Requested: ', session['user_profile']['name'])

        session.pop('show_login_form', False)
        session.pop('anon_id', None)

        if session.get('hold_story_id'):
            session['show_create'] = False
            session['show_stories'] = False
            session['show_account'] = False
            session['story_id'] = session.get('hold_story_id')
            session.pop('hold_story_id')
        else:
            session['show_create'] = True
    else:
        flash(error_msg)
    return redirect(url_for('index'))


def session_login(data, anon_id):
    id_token = data.get('idToken')
    decoded = firebase_auth.verify_id_token(id_token)
    if decoded:
        user_info = { 'uid': decoded['uid'], 'email': decoded.get('email') }
        user = user_info['uid']

    error_msg = ''
    # If logging in for the first time after creating account, load extra info into datastore
    name = data.get('name')
    birthdate = data.get('birthdate')
    if name and birthdate:
        key = ds_client.key('UserProfile', user)
        entity = ds_client.get(key) or datastore.Entity(key=key)
        entity['name'] = name
        entity['birthdate'] = birthdate
        try:
            ds_client.put(entity)
        except Exception as e:
            print("Datastore save failed:", e)
            error_msg = 'Could not save info. '

    # Add any anonymously created stories to a newly created/logged in user
    if anon_id:
        query = ds_client.query(kind='Story')
        query.add_filter('anon_id', '=', anon_id)
        for entity in query.fetch():
            entity['user'] = user
            entity['anon_id'] = None
            try:
                ds_client.put(entity)
            except Exception as e:
                print("Datastore save failed:", e)
                error_msg = error_msg + 'Could not save story. '

    response = {
        'user_info': user_info,
        'error_msg': error_msg + 'Please try again later.'
    }
    return response


@app.route('/session_logout', methods=['GET'])
def session_logout():
    session.clear()
    #session['show_login_form'] = True
    return redirect(url_for('index'))


def get_user_profile(user):
    user_profile = {}
    if user:
        print('user:', user)
        key = ds_client.key('UserProfile', user)
        profile_entity = ds_client.get(key) or {}
        user_profile = {
            'name': profile_entity.get('name', ''),
            'birthdate': profile_entity.get('birthdate', ''),
            'reading_level': profile_entity.get('reading_level', '')
        }
    else:
        print('user profile not found')
    return user_profile


@app.route('/api/v1/create_story', methods=['POST'])
def create_story_api():
    user, error = get_user_id()
    data = request.get_json()
    if not data:
        return jsonify({"error": "Missing JSON body"}), 400
    
    anon_id = None
    if not user:
        anon_id = data.get('anon_id')
        if not anon_id:
            return jsonify({"error": "Missing anon_id for anonymous user."}), 400

    story_id, story_set = create_story(data, user, anon_id)
    if story_id:
        return jsonify({
            "story_id": story_id,
            "story_set": story_set
        }), 201
    return jsonify({"error": "Failed to create story. Please try again."}), 500


@app.route('/create_story', methods=['POST'])
def create_story_web():
    user = session.get('user')
    anon_id = None
    if not user:
        anon_id = session.get('anon_id') or str(uuid.uuid4())
        session['anon_id'] = anon_id

    story_id, story_set = create_story(request.form, user, anon_id)
    session['story_id'] = story_id
    session['show_create'] = False
    if user:
        session['user_profile']['reading_level'] = request.form.get('reading_level')
    return redirect(url_for('index'))


def create_story(form_data, user=None, anon_id=None):
    # Map user input
    story_set = {
        'genre': form_data.get('genre'),
        'main_character': form_data.get('main_character'),
        'vibe_mood': form_data.get('vibe_mood'),
        'length': form_data.get('length'),
        'control': form_data.get('control'),
        'moral_lesson': form_data.get('moral_lesson'),
        'reader_age': form_data.get('reader_age'),
        'reading_level': form_data.get('reading_level'),
        'educational': form_data.get('educational'),
        'story': []
    }
    story_set = get_next_story_block(story_set, None)
    story_set['title'] = story_set['story'][0]['title']
    del story_set['story'][0]['title']

    if user:
        story_id = save_story_db(story_set, user)
        # Update default reading level
        key = ds_client.key('UserProfile', user)
        profile = ds_client.get(key) or datastore.Entity(key=key)
        profile['reading_level'] = form_data.get('reading_level')
        try:
            ds_client.put(profile)
        except Exception as e:
            logging.error(f"Datastore put failed: {e}")
            flash("Something went wrong saving your story. Please try again.")
    else:
        # store as anonymous user
        story_id = save_story_anonymous(story_set, anon_id)

    # Get image for story block, add to story block
    story_block = story_set['story'][-1]
    plot_block_summary = get_image_prompt_summary(story_block['summary'], story_block['text'], form_data.get('reading_level'))
    visual_desc_anchor = get_visual_description_anchor(story_block['text'], form_data.get('reading_level'))
    story_set['visual_desc'] = visual_desc_anchor
    story_block['image_url'] = get_book_picture(plot_block_summary, story_id, visual_desc_anchor, form_data.get('reading_level'))
    update_story_db(story_id, story_set)
    return story_id, story_set


def save_story_anonymous(story_set, anon_id=None):
    if story_set:
        key = ds_client.key('Story') 
        entity = datastore.Entity(key=key, exclude_from_indexes=['story'])
        entity.update({
            'title': story_set['title'],
            'genre': story_set['genre'],
            'main_character': story_set['main_character'],
            'vibe_mood': story_set['vibe_mood'],
            'length': story_set['length'],
            'control': story_set['control'],
            'moral_lesson': story_set['moral_lesson'],
            'reader_age': story_set['reader_age'],
            'reading_level': story_set['reading_level'],
            'educational': story_set['educational'],
            'story': json.dumps(story_set['story']),
            'created_at': datetime.now(timezone.utc),
            'last_modified': datetime.now(timezone.utc),
            'anon_id': anon_id
        })
        try:
            ds_client.put(entity)
        except Exception as e:
            print("Datastore save failed:", e)
            #flash("Something went wrong saving your story. Please try again.")
        print('Story saved with ID:', entity.key.id)
        story_id = entity.key.id
        return story_id


def save_story_db(story_set, user):
    #logging.info('Saving story to DB...')
    if story_set:
        key = ds_client.key('Story') 
        entity = datastore.Entity(key=key, exclude_from_indexes=['story'])
        entity.update({
            'title': story_set['title'],
            'genre': story_set['genre'],
            'main_character': story_set['main_character'],
            'vibe_mood': story_set['vibe_mood'],
            'length': story_set['length'],
            'control': story_set['control'],
            'moral_lesson': story_set['moral_lesson'],
            'reader_age': story_set['reader_age'],
            'reading_level': story_set['reading_level'],
            'educational': story_set['educational'],
            'story': json.dumps(story_set['story']),
            'created_at': datetime.now(timezone.utc),
            'last_modified': datetime.now(timezone.utc),
            'user': user
        })
        try:
            ds_client.put(entity)
        except Exception as e:
            print("Datastore save failed:", e)
            #flash("Something went wrong saving your story. Please try again.")
        print('Story saved with ID:', entity.key.id)
        story_id = entity.key.id
        #logging.info('Story saved to DB complete!')
        return story_id


@app.route('/api/v1/choose_path', methods=['POST'])
def choose_path_api():
    data = request.get_json()
    if not data:
        return jsonify({"error": "Missing JSON body"}), 400
    
    user, error = get_user_id()
    anon_id = None
    if not user:
        anon_id = data.get('anon_id')
        if not anon_id:
            return jsonify({"error": "Missing anon_id for anonymous user."}), 400
        
    story_id = data.get('story_id')
    if not story_id:
        return jsonify({"error": "Missing story_id."}), 400
    
    story_id, story_set = choose_path(story_id, data, user, anon_id)
    return jsonify({
        'story_id': story_id,
        'story_set': story_set
    }), 200

    
@app.route('/choose_path', methods=['POST'])
def choose_path_web():
    userprofile = session.get('user_profile')
    username = ''
    if userprofile:
        username = userprofile['name']
    print(f'{username or "Anon"}: Getting story block...')

    user = session.get('user')
    anon_id = session.get('anon_id')
    story_id = session.get('story_id')
    story_id, story_set = choose_path(story_id, request.form, user, anon_id)
    return redirect(url_for('index'))


def choose_path(story_id, form_data, user, anon_id):
    story_set = get_story(story_id, user, anon_id)

    decision = form_data['decision']
    next = form_data['next']
    choice = {'decision': decision, 'next': next}
    story_set = get_next_story_block(story_set, choice)

    # Get image for story block
    story_block = story_set['story'][-1]
    plot_block_summary = get_image_prompt_summary(story_block['summary'], story_block['text'], story_set['reading_level'])
    visual_desc_anchor = story_set['visual_desc']
    story_block['image_url'] = get_book_picture(plot_block_summary, story_id, visual_desc_anchor, story_set['reading_level'])

    update_story_db(story_id, story_set)
    return story_id, story_set


def update_story_db(story_id, story_set):
    key = ds_client.key('Story', story_id)
    try:
        entity = ds_client.get(key)
    except Exception as e:
        logging.error(f"Datastore get failed: {e}")
        flash("Could not retrieve story. Please try again later.")
    if entity:
        entity['story'] = json.dumps(story_set['story'])
        entity['visual_desc'] = story_set['visual_desc']
        entity['last_modified'] = datetime.now(timezone.utc)
        try:
            ds_client.put(entity)
        except Exception as e:
            print("Datastore save failed:", e)
            flash("Something went wrong saving your story. Please try again later.")
        print('Story updated with ID:', story_id)


@app.route('/api/v1/start_over', methods=['POST'])
def start_over_api():
    data = request.get_json()
    if not data:
        return jsonify({"error": "Missing JSON body"}), 400
    
    user, error = get_user_id()
    anon_id = None
    if not user:
        anon_id = data.get('anon_id')
        if not anon_id:
            return jsonify({"error": "Missing anon_id for anonymous user."}), 400
        
    story_id = data.get('story_id')
    if not story_id:
        return jsonify({"error": "Missing story_id."}), 400
    
    story_id, story_set = start_over(story_id, user, anon_id)
    if not story_set:
        return jsonify({"error": "Story not found or could not be reset."}), 404

    return jsonify({
        'story_id': story_id,
        'story_set': story_set
    }), 200


@app.route('/start_over', methods=['POST'])
def start_over_web():
    story_id = session.get('story_id')
    user = session.get('user')
    anon_id = session.get('anon_id')
    story_id, story_set = start_over(story_id, user, anon_id)
    return redirect(url_for('index'))


def start_over(story_id, user, anon_id):
    story_set = get_story(story_id, user, anon_id)
    if story_set:
        initial_story_block = story_set['story'][0]
        # Delete all images except the first block's image from GCS
        try:
            bucket = storage_client.bucket(BUCKET_NAME)
            blobs = bucket.list_blobs(prefix=f"stories/{story_id}/")
            first_image_url = initial_story_block.get('image_url', '')
            first_image_name = first_image_url.split('/')[-1] if first_image_url else ''
            for blob in blobs:
                if not blob.name.endswith(first_image_name):
                    try:
                        blob.delete()
                        print(f'Deleted image: {blob.name}')
                    except Exception as e:
                        logging.error(f"Error deleting blob: {e}")

        except Exception as e:
            print(f"Error deleting images for start_over: {e}")
        story_set['story'] = [initial_story_block]
        update_story_db(story_id, story_set)
        return story_id, story_set
    return story_id, {}


@app.route('/api/v1/go_back', methods=['POST'])
def go_back_api():
    data = request.get_json()
    if not data:
        return jsonify({"error": "Missing JSON body"}), 400
    
    user, error = get_user_id()
    anon_id = None
    if not user:
        anon_id = data.get('anon_id')
        if not anon_id:
            return jsonify({"error": "Missing anon_id for anonymous user."}), 400
        
    story_id = data.get('story_id')
    if not story_id:
        return jsonify({"error": "Missing story_id."}), 400
    
    story_id, story_set = go_back(story_id, user, anon_id)
    if not story_set:
        return jsonify({"error": "Story not found or could not be reset."}), 404

    return jsonify({
        'story_id': story_id,
        'story_set': story_set
    }), 200


@app.route('/go_back', methods=['POST'])
def go_back_web():
    user = session.get('user')
    anon_id = session.get('anon_id')
    story_id = session.get('story_id')
    story_id, story_set = go_back(story_id, user, anon_id)
    return redirect(url_for('index'))


def go_back(story_id, user, anon_id):
    story_set = get_story(story_id, user, anon_id)
    last_story_block = story_set['story'][-1]
    # Delete the image for this block from GCS
    image_url = last_story_block.get('image_url')
    if image_url:
        try:
            bucket = storage_client.bucket(BUCKET_NAME)
            blob_name = '/'.join(image_url.split('/')[-3:])  # assumes URL format
            blob = bucket.blob(blob_name)
            blob.delete()
            print(f'Deleted image for last block: {blob_name}')
        except Exception as e:
            print(f"Error deleting image for go_back: {e}")
    story_set['story'].remove(last_story_block)
    update_story_db(story_id, story_set)
    return story_id, story_set


@app.route('/reset', methods=['POST'])
def reset():
    session.pop('story_id', None)
    return redirect(url_for('index'))


@app.route('/api/v1/delete_story/<int:story_id>/<int:user>', methods=['POST'])
def delete_story_api(story_id, user):
    success = delete_story(story_id, user)
    if success:
        return '', 204
    return '', 404


@app.route('/delete_story/<int:story_id>', methods=['POST'])
def delete_story_web(story_id):
    user = session.get('user')
    success = delete_story(story_id, user)
    if not success:
        flash("Could not delete story. Please try again later.")
    return redirect(url_for('my_stories_web'))


def delete_story(story_id, user):
    if story_id and user:
        key = ds_client.key('Story', story_id)
        try:
            entity = ds_client.get(key)
        except Exception as e:
            logging.error(f"Datastore get failed: {e}")
            return False
        
        if entity and entity.get('user') == user:
            # Delete images in storage bucket
            bucket = storage_client.bucket(BUCKET_NAME)
            blobs = bucket.list_blobs(prefix=f"stories/{story_id}/")
            for blob in blobs:
                blob.delete()
            print(f'Deleted all images for Story ID: {story_id}')

            # Delete the Datastore entity
            ds_client.delete(key)
            print(f'Story ID: {story_id} deleted')
            return True
        return False


def get_all_stories_for_user(user):
    if not user:
        return []
    query = ds_client.query(kind='Story')
    query.add_filter('user', '=', user)
    all_stories = list(query.fetch())
    sorted_stories = sorted(all_stories, key=lambda x: x.get('last_modified'), reverse=True)
    return sorted_stories


def get_story(story_id, user, anon_id):
    key = ds_client.key('Story', story_id)
    try:
        entity = ds_client.get(key)
    except Exception as e:
        logging.error(f"Datastore get failed: {e}")
        return None

    if entity and (user and entity.get('user') == user) or (anon_id and entity.get('anon_id') == anon_id):
        story_set = {
            'title': entity.get('title'),
            'genre': entity.get('genre'),
            'main_character': entity.get('main_character'),
            'vibe_mood': entity.get('vibe_mood'),
            'length': entity.get('length'),
            'control': entity.get('control'),
            'moral_lesson': entity.get('moral_lesson'),
            'reader_age': entity.get('reader_age'),
            'reading_level': entity.get('reading_level'),
            'educational': entity.get('educational'),
            'story': json.loads(entity.get('story', '[]')),
            'visual_desc': entity.get('visual_desc'),
            'created_at': entity.get('created_at'),
            'last_modified': entity.get('last_modified')
        }
        return story_set
    return None


def get_scaled_lengths(story_set):
    """
    Scales the lengths (plot length map) of overall story and each story block (control map) based on reading level.
    Sets the unit of text to either 'paragraphs' or 'sentences' based on reading level. 
        (Used for younger reading levels where blocks are less than a paragraph)
    """
    
    reading_level = story_set['reading_level']
    control = story_set['control']
    length = story_set['length']

    # Pre-Primer
    if reading_level == 'prek':
        plot_length_map = {
            'quicky': 40,
            'novella': 60,
            'novel': 80,
            'epic': 100
        }
        control_map = {
            'low': 12,
            'medium': 8,
            'high': 6
        }
        text_unit = 'words'

    # Kindergarten
    elif reading_level == 'k':
        plot_length_map = {
            'quicky': 15,
            'novella': 30,
            'novel': 50,
            'epic': 100
        }
        control_map = {
            'low': 3,
            'medium': 2,
            'high': 1
        }
        text_unit = 'sentences'

    # 1st Grade
    elif reading_level == '1':
        plot_length_map = {
            'quicky': 30,
            'novella': 50,
            'novel': 80,
            'epic': 150
        }
        control_map = {
            'low': 5,
            'medium': 3,
            'high': 2
        }
        text_unit = 'sentences'

    # 2nd Grade
    elif reading_level == '2':
        plot_length_map = {
            'quicky': 50,
            'novella': 100,
            'novel': 150,
            'epic': 300
        }
        control_map = {
            'low': 10,
            'medium': 5,
            'high': 3
        }
        text_unit = 'sentences'

    # All other grade levels
    else:
        plot_length_map = {
            'quicky': 20,
            'novella': 100,
            'novel': 500,
            'epic': 1000
        }
        control_map = {
            'low': 8,
            'medium': 4,
            'high': 1
        }
        text_unit = 'paragraphs'

    total_blocks = plot_length_map.get(length)
    num_text_per_block = control_map.get(control)
    return total_blocks, num_text_per_block, text_unit


def map_user_set(story_set):
    """ Map user selections to specific prompt friendly variables """
    # Genre
    genre_map = {
        'fantasy': 'Fantasy adventure full of magical elements',
        'adventure': 'Exciting general adventure',
        'mystery': 'Fun mystery with clues to solve',
        'sci_fi': 'Science fiction with futuristic fun',
        'animal_story': 'Story about talking or helpful animals',
        'fairy_tale': 'Classic fairy tale vibe',
        'historical': 'Historical setting with age-appropriate details'
    }
    genre = genre_map.get(story_set['genre'])

    # Vibe/mood
    vibe_mood_map = {
        'silly_funny': 'Silly and funny mood',
        'heartwarming': 'Heartwarming and sweet',
        'inspirational': 'Inspirational and positive',
        'calm_relaxing': 'Calm and relaxing',
        'exciting_adventure': 'Full of excitement and adventure'
    }
    vibe_mood = vibe_mood_map.get(story_set['vibe_mood'], 'Default vibe mood')

    total_blocks, num_text_per_block, text_unit = get_scaled_lengths(story_set)

    # Moral lesson
    moral_lesson_map = {
        'None': '',
        'bravery': 'Include a moral lesson that teaches bravery',
        'kindness': 'Include a moral lesson that teaches kindness',
        'never_give_up': 'Include a moral lesson that teaches never giving up',
        'friendship': 'Include a moral lesson that teaches friendship',
        'family': 'Include a moral lesson that teaches family values',
        'teamwork': 'Include a moral lesson that teaches teamwork'
    }
    moral_lesson = moral_lesson_map.get(story_set['moral_lesson'])

    # Reader age map
    reader_age_map = {
        'under5': 'Under 5 years old',
        '5': '5 years old',
        '6': '6 years old',
        '7': '7 years old',
        '8': '8 years old',
        '9': '9 years old',
        '10': '10 years old',
        '11': '11 years old',
        '12': '12 years old',
        '13': '13 years old',
        '14plus': '14 years or older'
    }
    reader_age = reader_age_map.get(story_set['reader_age'], 'Age not specified')

    # Reading level map
    reading_level_map = {
        'prek': 'Pre-Primer reading level. Use sight words and keep sentences short and repetitive.',
        'k': 'Kindergarten reading level. Use sight words and keep sentences short and repetitive.',
        '1': '1st grade reading level',
        '2': '2nd grade reading level',
        '3': '3rd grade reading level',
        '4': '4th grade reading level',
        '5': '5th grade reading level',
        '6': '6th grade reading level',
        '7': '7th grade reading level',
        '8': '8th grade reading level',
        '9': '9th grade reading level',
        '10': '10th grade reading level',
        '11': '11th grade reading level',
        '12': '12th grade reading level'
    }
    reading_level = reading_level_map.get(story_set['reading_level'], 'Reading level not specified')

    # Main character (special 'me' input)
    if story_set.get('main_character') == 'me':
        if session.get('user_profile'):
            full_name = session['user_profile'].get('name', '')
            first_name = full_name.split(' ')[0] if full_name else 'The Reader'
            main_character = f'a kid named {first_name} who is {reader_age}'
    else:
        main_character_map = {
            'explorer': 'a brave explorer',
            'detective': 'a clever detective',
            'superhero': 'a superhero',
            'talking_animal': 'a talking animal',
            'inventor': 'a smart inventor',
            'everyday_hero': 'an everyday hero'
        }
        main_character = main_character_map.get(story_set['main_character'])

    # Educational
    educational_raw = story_set.get('educational')
    if educational_raw == 'true':
        educational = 'The story should be subtly educational and include age appropriate interesting facts to learn about.'
    else:
        educational = ''

    # Build final user setting map, using mapped reader_age and reading_level
    user_set = {
        'genre': genre,
        'main_character': main_character,
        'vibe_mood': vibe_mood,
        'length': total_blocks,
        'control': num_text_per_block,
        'moral_lesson': moral_lesson,
        'reader_age': reader_age,
        'reading_level': reading_level,
        'educational': educational,
        'text_unit': text_unit
    }
    return user_set


def get_next_story_block(story_set, choice=None):
    user_set = map_user_set(story_set)
    genre = user_set['genre']
    main_character = user_set['main_character']
    vibe_mood = user_set['vibe_mood']
    total_length = user_set['length']
    text_per_block = user_set['control']
    moral_lesson = user_set['moral_lesson']
    reader_age = user_set['reader_age']
    reading_level = user_set['reading_level']
    educational = user_set['educational']
    text_unit = user_set['text_unit']

    levels = ['prek', 'k', '1', '2']
    if story_set['reading_level'] in levels:
        parent_read = '- Make the story also be interesting and engaging to an adult parent of the child who is reading the story to the child. This includes adding some "easter-egg" style references that only a parent will notice.'
    else:
        parent_read = ''

    plot_blocks = story_set.get('story')
    if plot_blocks:
        last_block = story_set['story'][-1]
        summary = story_set['story'][-1]['summary']
        user_choice = choice.get('decision')

        text_used = len(story_set['story']) * text_per_block
        text_remaining = total_length - text_used
        if text_remaining <= text_per_block:
            # Last plot block, wrap up story, no more choices
            prompt = f"""
            You are writing the last {text_remaining} {text_unit} of the conclusion of a story. 

            Write the last part of the story ({text_per_block} {text_unit}), continuing naturally from the reader's choice.
            Let the reader's choice guide the continuation of the next part of the story you are writing now.
            But for now, the next section of the story, which should be {text_per_block} {text_unit}.
            Currently, the story's length is {len(plot_blocks) * text_per_block} {text_unit} long.
            So as the story is now, the story is { ((len(plot_blocks) * text_per_block) / total_length) * 100 }% of the way complete.
            This section of the story you write should resolve the absolute final conclusion of the story.
        
            Here is a story summary so far:
            \"{summary}\"

            Last section of the story so far:
            \"{last_block['text']}\"

            The reader chose to:
            \"{user_choice}\"

            Since this is the last final conclusion. There will be no more choices for the reader to make. So you can just put an empty string "" in place for each of the "decision" values.

            Respond ONLY with a valid JSON object like this 
            (Since this is the last plot story block. There will not be any decisions in the JSON object this time.
            Only put an empty string for the values in each decision key in the JSON object, as shown below):

            {{
            "text": "Next {text_per_block} {text_unit} story content...",
            "choices": [
                {{"decision": "", "next": 3}},
                {{"decision": "", "next": 4}}
            ],
            "summary": "Short updated summary of the plot so far."
            }}
            """.strip()

        else:
            # Continue story development for next plot block
            prompt = f"""
            You are continuing the next {text_per_block} {text_unit} of a story.

            This story will be built in sections. 
            So the overall length of this story when completed should total to {total_length} {text_unit}.
            But for now, write the next section of the story, which should be {text_per_block} {text_unit}.
            Currently, the story's length is {len(plot_blocks) * text_per_block} {text_unit} long. The total length of the story when it's done will need to be {total_length}.
            So as the story is now, the story is { ((len(plot_blocks) * text_per_block) / total_length) * 100 }% of the way complete.
            So, based on where the plot's current phase is (intro, arc, or conclusion), the next section you will write needs to reflect the current phase of the story, while progressing the plot based on the percentage of the story's progress, keeping in mind the total {text_unit} limit for the story.

            Here is a story summary so far:
            \"{summary}\"

            Last section of the story so far:
            \"{last_block['text']}\"

            The reader chose to:
            \"{user_choice}\"

            Write the next part of the story ({text_per_block} {text_unit}), continuing naturally from the reader's choice.
            This block should reflect the current arc: build tension toward the climax. The final conclusion should resolve within the last {text_per_block} {text_unit}.

            Important:
            - The total length of this story should be about {total_length} {text_unit} total.
            - You have already used approximately {text_used} {text_unit}.
            - That means you have ~{text_remaining} {text_unit} left to wrap up the full arc.
            - Plan the pacing and narrative arcs accordingly — don’t stall or wrap up too fast.

            """.strip()

    else:
        # Initial story creation, first plot block
        prompt = f"""
        Write the opening of the story, which should be {text_per_block} {text_unit}.

        This story will be built in sections, like a choose your own adventure style book. 
        So the overall length of this story when completed should total to {total_length} {text_unit}.
        But for now, only write the opening of the story, 
        But keep in mind the overall story intro, arc, and conclusion in the future will still be limited to {total_length} So ensure the plot structure follows this pace.

        """.strip()


    STATIC_SYSTEM_INSTRUCTIONS = f"""
        You are an creative and interactive “choose-your-own-adventure” style book author for children.
        
        Always follow these rules:
        - Use mostly Dolch words for a {reading_level}.
        - Keep the overall Lexile score within the typical range for a {reading_level}.
        - Set the content of the story to appeal to a child who is {reader_age}.
        - Use a {vibe_mood} tone.
        - Follow the genre: {genre}.
        - The main character is {main_character}.
        - {moral_lesson}
        - {educational}
        {parent_read}

        • Never mention, foreshadow, or allude to decision points or branching paths in the narrative itself;  
        all branching lives strictly in the `"choices"` array.

        Respond ONLY with a valid JSON object like this (replace the placeholder values of 'Choice A' and 'Choice B' in the JSON object example with the actual brief descriptions of each choice.):
        - Do NOT use generic placeholders such as "Choice A" or "Choice B". Each "decision" value must be a clear, descriptive option reflecting the actual branch.
        - For the summary: Think: “From the very beginning of the tale through the end of this block, what is the one‐paragraph full plot arc?” Do **not** summarize only the paragraphs you just wrote—summarize the entire arc so far.  

        {{
        "text": "Your story content here in {text_per_block} {text_unit}...",
        "choices": [
            {{"decision": "Choice A", "next": 1}},
            {{"decision": "Choice B", "next": 2}}
        ],
        "summary": "Brief cumulative summary of events so far.",
        "title": "Make up a brief title for this story."
        }}

    """.strip()

    #check_moderation(STATIC_SYSTEM_INSTRUCTIONS)
    print('STATIC: ', STATIC_SYSTEM_INSTRUCTIONS)
    print()
    print('PROMPT: ', prompt)

    response = openai_client.chat.completions.create(
        model="gpt-4o",
        messages=[
            {"role": "system", "content": STATIC_SYSTEM_INSTRUCTIONS},
            {"role": "user", "content": prompt}
        ],
        temperature=0.9,
        response_format={ "type": "json_object" }
    )
    try:
        text = response.choices[0].message.content
        if not text:
            flash("Oops! Something went wrong. Try selecting your choice again to continue your story.")
            raise ValueError("OPenAI response returned no content.")
        story_block = json.loads(text)
    except (json.JSONDecodeError, TypeError, ValueError) as e:
        print("JSON parsing error:", e)
        print("Response text was:", text)
        flash("Oops! Something went wrong. Try selecting your choice again to continue your story.")
        return story_set

    story_set['story'].append(story_block)
    #logging.info('STORY BLOCK CREATED')
    return story_set


def get_visual_description_anchor(full_text, reading_level):
    levels = ['prek', 'k']
    if reading_level in levels:
        illustration_style = "Describe the visual descriptions ultra simply so they can be drawn in a very simple, flat cartoon style for preschool kids. Bright solid colors only, and absolutely no shading, gradients, or texture descriptions. The description should resemble like clip-art for a preschool picture book: friendly, clear shapes, plain white or pastel background, no background details, no extra visual clutter. Characters should have big simple faces, clear emotions, and easy to recognize shapes."
    else:
        illustration_style = ""

    prompt = f"""
    Analyze this first story block:
    \"\"\"{full_text}\"\"\"
    Based on the main character and important visual elements such as accessories or other characters or sidekicks, create a single, clear, short visual description that can be reused for every illustration in the book to keep characters and details consistent.
    Include important details about the main character and any other characters like age, height, sex/gender, skin color, hair color, hair style/length, and eye color. 
    {illustration_style}
    """
    try:
        response = openai_client.chat.completions.create(
            model="gpt-4o",
            messages=[
                {"role": "system", "content": "You create reusable visual description anchors for children's book illustrations."},
                {"role": "user", "content": prompt}
            ],
            temperature=0.3
        )
        visual_desc = response.choices[0].message.content.strip()
        return visual_desc
    except Exception as e:
        print('Could not get visual description anchor: >>>>>>>> ', e)
        return ''


def get_image_prompt_summary(plot_summary, text_block: str, reading_level):
    print('Prompting for image...')
    #logging.info('Prompting for image')
    levels = ['prek', 'k']
    if reading_level in levels:
        illustration_style = "Describe the scene so it can be drawn in a very simple, flat cartoon style for preschool kids. Bright solid colors only, and absolutely no shading, gradients, or texture descriptions. The description should resemble like clip-art for a preschool picture book: friendly, clear shapes, plain white or pastel background, no background details, no extra visual clutter. Characters should have big simple faces, clear emotions, and easy to recognize shapes."
    else:
        illustration_style = ""

    prompt = f"""
    This is the next story section of the book: {text_block}
    Create a concise, clear prompt that could be used to illustrate these particular scenes/events in this story section for kids.
    Include as detailed visual descriptions to keep the prompt describing the current scene well while keeping the details consistent from the cumulative plot story summary.
    {illustration_style}
    """.strip()

    STATIC_SYSTEM_INSTRUCTIONS = f"""
    You help create clear, short image prompts for children's book illustrations.
    The cumulative plot story summary for the book so far is {plot_summary}.
    Except for names of characters. Ensure no other text appears in the image itself.
    """.strip()
    try:
        response = openai_client.chat.completions.create(
            model="gpt-4o",
            messages=[
                {"role": "system", "content": STATIC_SYSTEM_INSTRUCTIONS},
                {"role": "user", "content": prompt}
            ],
            temperature=0.3
        )
        summary_text = response.choices[0].message.content.strip()
        print('Summary prompt:', summary_text)
        return summary_text
    except Exception as e:
        print('Could not get image prompt summary from OpenAI')
        return ''


def get_book_picture(image_prompt: str, story_id, visual_description, reading_level):
    """
    Receives summary of story block as an image prompt format
    Returns a url of the location of the stored image on Google Cloud Bucket
    """
    print('Creating book illustration...')
    print()
    print('IMAGE PROMPT: ', image_prompt)
    print()
    print('VISUAL DESC: ', visual_description)
    print()

    levels = ['prek', 'k']
    if reading_level in levels:
        print('Pre-k to K grade style illustrations')
        illustration_style = "Draw in a very simple, flat cartoon style for preschool kids. Use clear bold outlines, bright solid colors only, and absolutely no shading, gradients, or textures. The drawing should look like clip-art for a preschool picture book: friendly, clear shapes, plain white or pastel background, no background details, no extra visual clutter. Characters should have big simple faces, clear emotions, and easy to recognize shapes."
    else:
        print('1st grade and above illustrations')
        illustration_style = "A watercolor style, colorful, kid-friendly children's book cartoon illustration:"

    # Send prompt for image
    try:
        image_response = openai_client.images.generate(
            model="dall-e-3",
            prompt=f"""
            Visual anchor (always use):
            \"{visual_description}\"

            Scene to illustrate:
            {illustration_style} {image_prompt}.

            Combine both: The final illustration must match the anchor details and depict the scene in the story.
            """,
            n=1,
            size="1024x1024"
        )
        image_url = image_response.data[0].url

        # Download image to memory
        response = requests.get(image_url)
        if response.status_code != 200:
            print(f"Failed to download image: {response.status_code}")
            return None

        img_bytes = io.BytesIO(response.content)
        if not img_bytes:
            print('OpenAI Failed to generate image')
        else:
            print('OpenAI Image Creation success')
        # Upload image to GCS Bucket
        bucket = storage_client.bucket(BUCKET_NAME)
        unique_id = uuid.uuid4().hex
        blob_name = f"stories/{story_id}/block_{unique_id}.png"
        blob = bucket.blob(blob_name)
        blob.upload_from_file(img_bytes, content_type='image/png')
        return blob.public_url
    
    except Exception as e:
        print("ERROR in image generation/storage:", str(e))
        #logging.info('Error in image generation/storage:', str(e))
        return ''
    

@app.errorhandler(500)
def internal_error(error):
    logging.exception(f"Internal server error: {error}")
    return render_template('500.html'), 500


@app.errorhandler(404)
def not_found_error(error):
    logging.warning(f"Page not found: {error}")
    return render_template('404.html'), 404


# Check if prompt violates OpenAI's moderation policies
def check_moderation(input_text: str):
    response = openai_client.moderations.create(
        model="omni-moderation-latest",
        input=input_text
    )
    flagged = response.results[0].flagged
    categories = response.results[0].categories
    print(response, categories)
    return flagged, categories


# cron handler to remove non registered account user's stories from database (triggered daily)
@app.route('/cron/cleanup_anonymous', methods=['GET'])
def cleanup_anonymous():
    """Delete anonymous stories older than 30 days and associated images."""
    cutoff = datetime.now(timezone.utc) - timedelta(days=30)
    query = ds_client.query(kind='Story')
    query.add_filter('user', '==', None)
    query.add_filter('created_at', '<', cutoff)
    expired = list(query.fetch())

    bucket = storage_client.bucket(BUCKET_NAME)

    for entity in expired:
        story_id = entity.key.id

        # Delete images for this story
        blobs = bucket.list_blobs(prefix=f"stories/{story_id}/")
        for blob in blobs:
            blob.delete()
            print(f"Deleted blob: {blob.name}")

        # Delete the Datastore entity
        ds_client.delete(entity.key)
        print(f"Deleted expired anon story ID: {story_id}")

    print(f"Total expired anon stories cleaned: {len(expired)}")
    return ('', 204)


if __name__ == "__main__":
    app.run(host='0.0.0.0', port=8080, debug=True)

    #app.run(debug=True)