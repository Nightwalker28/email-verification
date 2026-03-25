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

const buildPredictionCell = (details) => {
    const wrapper = $('<div>').addClass('expandable-cell');
    const summary = $('<div>').addClass('cell-summary');
    const predictedResult = details.predicted_result || '-';
    summary.append($('<span>').addClass('cell-main').text(predictedResult));
    if (details.predicted_validity_score !== null && details.predicted_validity_score !== undefined) {
        summary.append(
            $('<button>')
                .attr('type', 'button')
                .addClass('expand-toggle')
                .attr('aria-expanded', 'false')
                .text('...')
        );
        const panel = $('<div>').addClass('cell-panel hidden');
        panel.append($('<div>').text(`Valid: ${Math.round((details.predicted_validity_score || 0) * 100)}%`));
        panel.append($('<div>').text(`Risky: ${Math.round((details.predicted_risky_score || 0) * 100)}%`));
        panel.append($('<div>').text(`Invalid: ${Math.round((details.predicted_invalid_score || 0) * 100)}%`));
        wrapper.append(summary, panel);
        return wrapper;
    }
    wrapper.append(summary);
    return wrapper;
};

const buildProviderCell = (details) => {
    const wrapper = $('<div>').addClass('expandable-cell');
    const summary = $('<div>').addClass('cell-summary');
    summary.append($('<span>').addClass('cell-main').text(details.provider || '-'));
    if (details.provider_ml) {
        summary.append(
            $('<button>')
                .attr('type', 'button')
                .addClass('expand-toggle')
                .attr('aria-expanded', 'false')
                .text('...')
        );
        const panel = $('<div>').addClass('cell-panel hidden');
        panel.append($('<div>').text(`ML: ${details.provider_ml}`));
        if (details.provider_ml_score !== null && details.provider_ml_score !== undefined) {
            panel.append($('<div>').text(`Confidence: ${Math.round(details.provider_ml_score * 100)}%`));
        }
        wrapper.append(summary, panel);
        return wrapper;
    }
    wrapper.append(summary);
    return wrapper;
};

const buildRoleCell = (details) => {
    const wrapper = $('<div>').addClass('expandable-cell');
    const summary = $('<div>').addClass('cell-summary');
    summary.append($('<span>').addClass('cell-main').text(details.role_based || '-'));
    if (details.role_ml_result || details.role_score !== null && details.role_score !== undefined) {
        summary.append(
            $('<button>')
                .attr('type', 'button')
                .addClass('expand-toggle')
                .attr('aria-expanded', 'false')
                .text('...')
        );
        const panel = $('<div>').addClass('cell-panel hidden');
        panel.append($('<div>').text(`ML: ${details.role_ml_result || 'Unknown'}`));
        if (details.role_score !== null && details.role_score !== undefined) {
            panel.append($('<div>').text(`Score: ${Math.round(details.role_score * 100)}%`));
        }
        wrapper.append(summary, panel);
        return wrapper;
    }
    wrapper.append(summary);
    return wrapper;
};

const buildSpoofCell = (details) => {
    const wrapper = $('<div>').addClass('expandable-cell');
    const summary = $('<div>').addClass('cell-summary');
    summary.append($('<span>').addClass('cell-main').text(details.spoofed_domain || '-'));
    if (details.spoof_score !== null && details.spoof_score !== undefined) {
        summary.append(
            $('<button>')
                .attr('type', 'button')
                .addClass('expand-toggle')
                .attr('aria-expanded', 'false')
                .text('...')
        );
        const panel = $('<div>').addClass('cell-panel hidden');
        panel.append($('<div>').text(`Brand: ${details.spoof_brand || '-'}`));
        panel.append($('<div>').text(`Score: ${Math.round(details.spoof_score * 100)}%`));
        wrapper.append(summary, panel);
        return wrapper;
    }
    wrapper.append(summary);
    return wrapper;
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
      existingRow.children('td:nth-child(3)').empty().append(buildPredictionCell(details));
      existingRow.children('td:nth-child(4)').empty().append(buildProviderCell(details));
      existingRow.children('td:nth-child(5)').empty().append(buildRoleCell(details));
      existingRow.children('td:nth-child(6)').empty().append(buildSpoofCell(details));
      existingRow.children('td:nth-child(7)').text(details.accept_all);
      existingRow.children('td:nth-child(8)').text(details.full_inbox);
      existingRow.children('td:nth-child(9)').text(details.temporary_mail);
      tableBody.prepend(existingRow);
    } else {
      
      const newRow = $('<tr>');
      newRow.append($('<td>').text(email));
      newRow.append($('<td>').addClass(`status-${details.result.toLowerCase().replace(/ /g, '-')}`).text(details.result));
      newRow.append($('<td>').append(buildPredictionCell(details)));
      newRow.append($('<td>').append(buildProviderCell(details)));
      newRow.append($('<td>').append(buildRoleCell(details)));
      newRow.append($('<td>').append(buildSpoofCell(details)));
      newRow.append($('<td>').text(details.accept_all));
      newRow.append($('<td>').text(details.full_inbox));
      newRow.append($('<td>').text(details.temporary_mail));

      tableBody.prepend(newRow);

      if (isHomePageTable) {
        
        while (tableBody.children('tr').length > 1) {
          tableBody.children('tr').last().remove();
        }
        
        const noResultsRow = tableBody.find('td[colspan="9"]');
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

$(document).on('click', '.expand-toggle', function() {
    const button = $(this);
    const panel = button.closest('.expandable-cell').find('.cell-panel').first();
    const isHidden = panel.hasClass('hidden');
    panel.toggleClass('hidden', !isHidden);
    button.attr('aria-expanded', String(isHidden));
});


const performVerification = (url, emailAddress, buttonElement, originalButtonText) => {
    
    setButtonLoading(buttonElement, true, originalButtonText);
    const startedAt = Date.now();
    
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
          let predictionTimer = null;
          let finalReceived = false;

          const maybeShowPrediction = (eventData) => {
            if (finalReceived) return;
            updateResultsTable(eventData.email, eventData.details);
            displayMessage(`Prediction ready for ${eventData.email}: ${eventData.details.prediction_summary || 'pending'}. Live check still running...`, false);
          };

          eventSource.onmessage = function(event) {
            const eventData = JSON.parse(event.data);
            console.log("Received SSE data:", eventData);
            if (eventData.status === 'predicted') {
              const elapsed = Date.now() - startedAt;
              const remaining = Math.max(0, 3000 - elapsed);
              if (predictionTimer) clearTimeout(predictionTimer);
              predictionTimer = setTimeout(() => maybeShowPrediction(eventData), remaining);
            } else if (eventData.status === 'completed') {
              finalReceived = true;
              if (predictionTimer) clearTimeout(predictionTimer);
              updateResultsTable(eventData.email, eventData.details);
              displayMessage(`Verification for ${eventData.email} completed.`, false);
              $('#emailAddress').val('').focus(); 
              eventSource.close();
              
              setButtonLoading(buttonElement, false, originalButtonText);
            } else if (eventData.status === 'error' || eventData.status === 'failed') {
              finalReceived = true;
              if (predictionTimer) clearTimeout(predictionTimer);
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
