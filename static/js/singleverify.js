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
    }, 1000);
}


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


const updateResultsTable = (email, details) => {
  
  const updateSpecificTable = (tableBodySelector, isHomePageTable = false) => {
    const tableBody = $(tableBodySelector);
    if (!tableBody.length) return; 

    let existingRow = null;
    tableBody.children('tr').each(function() {
      const row = $(this);
      if (row.children('td:first-child').text() === email) {
        existingRow = row;
        return false; 
      }
    });

    if (existingRow) {
      
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
        
        while (tableBody.children('tr').length > 1) {
          tableBody.children('tr').last().remove();
        }
        
        const noResultsRow = tableBody.find('td[colspan="7"]');
        if (noResultsRow.length) {
            noResultsRow.parent().remove();
        }
      } else {
        
        const maxRows = 10;
        while (tableBody.children('tr').length > maxRows) {
          tableBody.children('tr').last().remove();
        }
      }
    }

    
    if (!isHomePageTable) {
        const emptyState = $('.results-container .empty-state'); 
        const tableResponsive = $('#lastCheckedEmailsTable').closest('.table-responsive'); 
        if (emptyState.length && tableResponsive.length) {
            if (tableBody.children('tr').length > 0) {
                emptyState.hide();
                tableResponsive.show();
            }
        }
    }
  };

  
  updateSpecificTable('#lastCheckedEmailsTable tbody', false);
  
  updateSpecificTable('#homeRecentResultsTableBody', true);
};


const performVerification = (url, emailAddress, buttonElement, originalButtonText) => {
    
    setButtonLoading(buttonElement, true, originalButtonText);
    
    $.ajax({
      url: url,
      type: 'POST',
      contentType: 'application/json',
      data: JSON.stringify({ email: emailAddress }),
      success: (response, status, xhr) => {
        
        
        const taskId = response.data.task_id;

        if (taskId) {
          displayMessage('Verification started. Waiting for results...', false);
          const eventSource = new EventSource('/status-sse/' + taskId);

          eventSource.onmessage = function(event) {
            const eventData = JSON.parse(event.data);
            console.log("Received SSE data:", eventData);
            if (eventData.status === 'completed') {
              updateResultsTable(eventData.email, eventData.details);
              displayMessage(`Verification for ${eventData.email} completed.`, false);
              $('#emailAddress').val('').focus(); 
              eventSource.close();
              
              setButtonLoading(buttonElement, false, originalButtonText);
            } else if (eventData.status === 'error' || eventData.status === 'failed') {
              displayMessage(`Verification task error for ${emailAddress}: ${eventData.message || 'Unknown error'}`, true);
              eventSource.close();
              
              setButtonLoading(buttonElement, false, originalButtonText);
            }
          };

          eventSource.onerror = function(err) {
            console.error("EventSource failed:", err);
            displayMessage('Error receiving real-time updates. Please refresh to see results.', true);
            eventSource.close();
            
            setButtonLoading(buttonElement, false, originalButtonText);
          };
        }
      },
      error: (xhr) => {
        
        setButtonLoading(buttonElement, false, originalButtonText);
        const errorMessage = xhr.responseJSON?.error || "An error occurred";
        displayMessage(errorMessage, true);
      }
    });
};

$(document).ready(() => {
    
    
    const verifyPageVerifyButton = $('#manualEmailForm button[type="submit"]').not('.home-container #manualEmailForm button[type="submit"]'); 
    const verifyPageForceButton = $('#forceVerifyBtn');
    const originalVerifyPageVerifyText = verifyPageVerifyButton.length ? verifyPageVerifyButton.html() : 'Verify Email';
    const originalVerifyPageForceText = verifyPageForceButton.length ? verifyPageForceButton.html() : 'Force Verify';

    
    const homePageVerifyButton = $('.home-container #manualEmailForm button[type="submit"]');
    const originalHomePageVerifyText = homePageVerifyButton.length ? homePageVerifyButton.html() : 'Verify Now';
    
    
    $('#manualEmailForm').not('.home-container #manualEmailForm').on('submit', (event) => { 
        event.preventDefault();
        const emailAddress = $('#emailAddress').val();
        performVerification('/verify', emailAddress, verifyPageVerifyButton, originalVerifyPageVerifyText);
    });

    
    $('.home-container #manualEmailForm').on('submit', (event) => {
        event.preventDefault();
        const emailAddress = $('.home-container #emailAddress').val(); 
        performVerification('/verify', emailAddress, homePageVerifyButton, originalHomePageVerifyText);
    });

    
    if (verifyPageForceButton.length) {
        verifyPageForceButton.on('click', () => {
            const emailAddress = $('#emailAddress').val();
            performVerification('/force-verify', emailAddress, verifyPageForceButton, originalVerifyPageForceText);
        });
    }
});
