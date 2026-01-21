let alertTimeout;
function displayMessage(message, isError = false) {
    const messageContainer = $('#message-container');
    messageContainer.removeClass('alert-success alert-danger show');
    messageContainer.addClass(isError ? 'alert-danger' : 'alert-success');
    messageContainer.text(message);

    setTimeout(() => {
        messageContainer.addClass('show');
    }, 10);

    if (alertTimeout) clearTimeout(alertTimeout);
    alertTimeout = setTimeout(() => {
        messageContainer.removeClass('show');
    }, 5000);
}

// Helper function to show loading state on button
const setButtonLoading = (button, isLoading, originalText) => {
    if (isLoading) {
        button.prop('disabled', true);
        button.html(`
            <span style="display: inline-flex; align-items: center; justify-content: center; gap: 8px;">
                <div class="spinner"></div>
                <span>Verifying...</span>
            </span>
        `);
    } else {
        button.prop('disabled', false);
        button.html(originalText);
    }
};

// Helper function to update the results table dynamically
const updateResultsTable = (email, details) => {
  // Function to update a single table
  const updateSpecificTable = (tableBodySelector, isHomePageTable = false) => {
    const tableBody = $(tableBodySelector);
    if (!tableBody.length) return; // Skip if table body doesn't exist

    let existingRow = null;
    tableBody.children('tr').each(function() {
      const row = $(this);
      if (row.children('td:first-child').text() === email) {
        existingRow = row;
        return false; // Break the loop
      }
    });

    if (existingRow) {
      // Update existing row
      existingRow.children('td:nth-child(2)')
        .removeClass((index, className) => (className.match(/(^|\s)status-\S+/g) || []).join(' '))
        .addClass(`status-${details.result.toLowerCase().replace(/ /g, '-')}`)
        .text(details.result);
      existingRow.children('td:nth-child(3)').text(details.provider);
      existingRow.children('td:nth-child(4)').text(details.role_based);
      existingRow.children('td:nth-child(5)').text(details.accept_all);
      existingRow.children('td:nth-child(6)').text(details.full_inbox);
      existingRow.children('td:nth-child(7)').text(details.temporary_mail);
      tableBody.prepend(existingRow);
    } else {
      // Add new row
      const newRow = $('<tr>');
      newRow.append($('<td>').text(email));
      newRow.append($('<td>').addClass(`status-${details.result.toLowerCase().replace(/ /g, '-')}`).text(details.result));
      newRow.append($('<td>').text(details.provider));
      newRow.append($('<td>').text(details.role_based));
      newRow.append($('<td>').text(details.accept_all));
      newRow.append($('<td>').text(details.full_inbox));
      newRow.append($('<td>').text(details.temporary_mail));

      tableBody.prepend(newRow);

      if (isHomePageTable) {
        // Home page table only shows 1 row
        while (tableBody.children('tr').length > 1) {
          tableBody.children('tr').last().remove();
        }
        // Ensure the "No recent verifications" message is handled if it was there
        const noResultsRow = tableBody.find('td[colspan="7"]');
        if (noResultsRow.length) {
            noResultsRow.parent().remove();
        }
      } else {
        // Verify page table limits to maxRows
        const maxRows = 10;
        while (tableBody.children('tr').length > maxRows) {
          tableBody.children('tr').last().remove();
        }
      }
    }

    // Handle empty state for the verify page table
    if (!isHomePageTable) {
        const emptyState = $('.results-container .empty-state'); // Specific to verify.html structure
        const tableResponsive = $('#lastCheckedEmailsTable').closest('.table-responsive'); // Specific to verify.html
        if (emptyState.length && tableResponsive.length) {
            if (tableBody.children('tr').length > 0) {
                emptyState.hide();
                tableResponsive.show();
            }
        }
    }
  };

  // Update verify page table (if it exists)
  updateSpecificTable('#lastCheckedEmailsTable tbody', false);
  // Update home page table (if it exists)
  updateSpecificTable('#homeRecentResultsTableBody', true);
};

// Helper function to update attempts badge
const updateAttemptsBadge = (attemptsRemaining) => {
  if (attemptsRemaining !== undefined) {
    const attemptsSpan = $('#attempts-remaining-count');
    if (attemptsSpan.length) {
      attemptsSpan.text(attemptsRemaining);
    } else {
      // If the badge needs to be created dynamically (e.g. user was paid, now free)
      // This might be more complex and involve recreating the badge div.
      // For now, we only update if the span exists.
      // A full page reload might be simpler if the entire badge structure changes.
      // Consider if the parent .attempts-badge should be shown/hidden.
      // For now, just updating the number.
    }
  };
};

// Helper function to perform email verification via AJAX.
const performVerification = (url, emailAddress, buttonElement, originalButtonText) => {
    // Show loading state on the clicked button
    setButtonLoading(buttonElement, true, originalButtonText);
    
    $.ajax({
      url: url,
      type: 'POST',
      contentType: 'application/json',
      data: JSON.stringify({ email: emailAddress }),
      success: (response, status, xhr) => {
        
  
        // Check if this is a silent HTML redirect (Flask sending the pricing page)
        if (
          typeof response === "string" &&
          response.includes('<title>Pricing') // or any unique element on the pricing page
        ) {
          window.location.href = '/pricing';
          return;
        }
  
        // Normal success path - Start SSE listening
        const taskId = response.data.task_id;
        if (response.data.attempts_remaining !== undefined) {
          updateAttemptsBadge(response.data.attempts_remaining);
        }

        if (taskId) {
          displayMessage('Verification started. Waiting for results...', false);
          const eventSource = new EventSource('/status-sse/' + taskId);

          eventSource.onmessage = function(event) {
            const eventData = JSON.parse(event.data);
            console.log("Received SSE data:", eventData);
            if (eventData.status === 'completed') {
              updateResultsTable(eventData.email, eventData.details);
              displayMessage(`Verification for ${eventData.email} completed.`, false);
              eventSource.close();
              // Reset button state
              setButtonLoading(buttonElement, false, originalButtonText);
            } else if (eventData.status === 'error' || eventData.status === 'failed') {
              displayMessage(`Verification task error for ${emailAddress}: ${eventData.message || 'Unknown error'}`, true);
              eventSource.close();
              // Reset button state
              setButtonLoading(buttonElement, false, originalButtonText);
            }
          };

          eventSource.onerror = function(err) {
            console.error("EventSource failed:", err);
            displayMessage('Error receiving real-time updates. Please refresh to see results.', true);
            eventSource.close();
            // Reset button state
            setButtonLoading(buttonElement, false, originalButtonText);
          };
        }
      },
      error: (xhr) => {
        // Reset button state
        setButtonLoading(buttonElement, false, originalButtonText);
  
        // Fallback: detect if redirect HTML landed in error handler
        if (xhr.status === 200 && xhr.responseText && xhr.responseText.includes('<title>Pricing')) {
          window.location.href = '/pricing';
          return;
        }
  
        const errorMessage = xhr.responseJSON?.error || "An error occurred";
        displayMessage(errorMessage, true);
      }
    });
};

$(document).ready(() => {
    // Store original button texts when the page loads
    // For verify.html
    const verifyPageVerifyButton = $('#manualEmailForm button[type="submit"]').not('.home-container #manualEmailForm button[type="submit"]'); // Exclude home page button
    const verifyPageForceButton = $('#forceVerifyBtn');
    const originalVerifyPageVerifyText = verifyPageVerifyButton.length ? verifyPageVerifyButton.html() : 'Verify Email';
    const originalVerifyPageForceText = verifyPageForceButton.length ? verifyPageForceButton.html() : 'Force Verify';

    // For home.html
    const homePageVerifyButton = $('.home-container #manualEmailForm button[type="submit"]');
    const originalHomePageVerifyText = homePageVerifyButton.length ? homePageVerifyButton.html() : 'Verify Now';
    
    // Handle manual verification on verify.html
    $('#manualEmailForm').not('.home-container #manualEmailForm').on('submit', (event) => { // Exclude home page form
        event.preventDefault();
        const emailAddress = $('#emailAddress').val();
        performVerification('/verify', emailAddress, verifyPageVerifyButton, originalVerifyPageVerifyText);
    });

    // Handle manual verification on home.html
    $('.home-container #manualEmailForm').on('submit', (event) => {
        event.preventDefault();
        const emailAddress = $('.home-container #emailAddress').val(); // Get email from home page input
        performVerification('/verify', emailAddress, homePageVerifyButton, originalHomePageVerifyText);
    });

    // Handle forced verification on verify.html (only if the button exists)
    if (verifyPageForceButton.length) {
        verifyPageForceButton.on('click', () => {
            const emailAddress = $('#emailAddress').val();
            performVerification('/force-verify', emailAddress, verifyPageForceButton, originalVerifyPageForceText);
        });
    }
});