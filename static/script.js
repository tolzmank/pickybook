
// Table sorting behavior
document.addEventListener('DOMContentLoaded', () => {
  const getCellValue = (tr, idx) => {
    const cell = tr.children[idx];
    return cell ? cell.textContent.trim() : '';
  };

  const comparer = (idx, asc) => (a, b) => {
    const v1 = getCellValue(a, idx);
    const v2 = getCellValue(b, idx);
    const numericRegex = /^[-+]?\d+(\.\d+)?$/;
    const isNum1 = numericRegex.test(v1);
    const isNum2 = numericRegex.test(v2);
    if (isNum1 && isNum2) {
      const num1 = parseFloat(v1.replace(/[^0-9.\-]+/g, ''));
      const num2 = parseFloat(v2.replace(/[^0-9.\-]+/g, ''));
      return asc ? num1 - num2 : num2 - num1;
    }
    return asc ? v1.localeCompare(v2) : v2.localeCompare(v1);
  };

  document.querySelectorAll('table th:not(.no-sort)').forEach((th) => {
    let asc = true;
    th.addEventListener('click', () => {
      const table = th.closest('table');
      const tbody = table.querySelector('tbody');
      Array.from(tbody.querySelectorAll('tr'))
        .sort(comparer(Array.from(th.parentNode.children).indexOf(th), asc))
        .forEach(row => tbody.appendChild(row));
      asc = !asc;
      
      // Update header indicators
      table.querySelectorAll('th').forEach(h => {
        h.classList.remove('sorttable_sorted', 'sorttable_sorted_reverse');
      });
      th.classList.toggle(asc ? 'sorttable_sorted_reverse' : 'sorttable_sorted');
    });
  });

  // Toggle all row checkboxes when header checkbox is clicked
  const selectAllCheckbox = document.getElementById('select-all');

  function updateModifyButtons() {
    const anyChecked = Array.from(document.querySelectorAll('input[name="selected_models"]'))
      .some(cb => cb.checked);
    const deleteBtn = document.getElementById('delete-selected-btn');
    if (deleteBtn) {
      deleteBtn.style.display = anyChecked ? 'inline-block' : 'none';
    }
    // Compare button toggle
    const compareBtn = document.getElementById('compare-selected-btn');
    const dateRange = document.getElementById('compare-selected-date-range')
    if (compareBtn) {
      compareBtn.style.display = anyChecked ? 'inline-block' : 'none';
    }
    if (dateRange) {
      dateRange.style.display = anyChecked ? 'inline-block' : 'none';
    }
  }
  
  document.querySelectorAll('input[name="selected_models"]').forEach(cb => {
    cb.addEventListener('change', updateModifyButtons);
  });


  if (selectAllCheckbox) {
    selectAllCheckbox.addEventListener('change', () => {
      document.querySelectorAll('input[name="selected_models"]').forEach(cb => {
        cb.checked = selectAllCheckbox.checked;
      });
      updateModifyButtons();
    });
  }


  updateModifyButtons();

  // Delete model confirmation
  const deleteBtn = document.getElementById('delete-selected-btn');
  if (deleteBtn) {
    deleteBtn.addEventListener('click', function() {
      if (confirm('Are you sure you want to delete the selected models?')) {
        deleteBtn.closest('form').submit();
      }
    });
  }

    // Delete user confirmation
  const deleteUserBtn = document.getElementById('delete-user');
  if (deleteUserBtn) {
    deleteBtn.addEventListener('click', function() {
      if (confirm('Are you sure you want to delete this user?')) {
        deleteUserBtn.closest('form').submit();
      }
    });
  }

  // Change image on hover
  document.querySelectorAll('img[data-hover-src]').forEach(img => {
    const defaultSrc = img.getAttribute('data-default-src');
    const hoverSrc   = img.getAttribute('data-hover-src');
    img.addEventListener('mouseenter', () => img.src = hoverSrc);
    img.addEventListener('mouseleave', () => img.src = defaultSrc);
  });




  

});
