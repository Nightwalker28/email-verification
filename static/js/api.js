function displayMessage(message, isError = false) {
    const messageContainer = $('#message-container');
    messageContainer.removeClass('d-none alert-success alert-danger');
    messageContainer.addClass(isError ? 'alert-danger' : 'alert-success');
    messageContainer.text(message);
    messageContainer.show();
    setTimeout(() => messageContainer.hide(), 5000);
  }
  
  $(document).ready(() => {
    $('#createApiKeyBtn').on('click', () => $('#createApiKeyModal').show());
    $('#closeModalBtn').on('click', () => $('#createApiKeyModal').hide());
  
    $('#createApiKeyForm').on('submit', function (event) {
      event.preventDefault();
      $.ajax({
        type: 'POST',
        url: '/create_api',
        data: $(this).serialize(),
        success: (response) => {
          if (response.success) {
            $('#successMessage').text(response.success);
            $('#successModal').show();
            $('#createApiKeyModal').hide();
            // Extract API key and set for copying
            const apiKey = response.success.split('Your API key is: ')[1];
            $('#apiKeyText').text(apiKey);
          }
        },
        error: (xhr) => {
          const errorMessage = xhr.responseJSON ? xhr.responseJSON.error : "An error occurred";
          displayMessage(errorMessage, true);
        }
      });
    });
  
    $('#closeSuccessModalBtn').on('click', () => {
      $('#successModal').hide();
      window.location.reload();
    });
  
    $('#copyApiKeyBtn').on('click', () => {
      const apiKey = $('#apiKeyText').text();
      navigator.clipboard.writeText(apiKey)
        .then(() => displayMessage('Key Copied Successfully'))
        .catch((err) => {
          console.error('Could not copy text:', err);
          displayMessage('Failed to copy the API key', true);
        });
    });
  
    $('.editApiKeyBtn').on('click', function () {
      const row = $(this).closest('tr');
      const apiKeyId = row.data('id');
      const apiKeyName = row.find('td:first').text();
      $('#editApiKeyId').val(apiKeyId);
      $('#editName').val(apiKeyName);
      $('#editApiKeyModal').show();
    });
  
    $('#closeEditModalBtn').on('click', () => $('#editApiKeyModal').hide());
  
    $('#editApiKeyForm').on('submit', function (event) {
      event.preventDefault();
      $.ajax({
        type: 'POST',
        url: '/edit_api',
        data: $(this).serialize(),
        success: () => location.reload(),
        error: (xhr) => {
          const errorMessage = xhr.responseJSON ? xhr.responseJSON.error : "An error occurred";
          displayMessage(errorMessage, true);
        }
      });
    });
  
    $('.deleteApiKeyBtn').on('click', function () {
      const row = $(this).closest('tr');
      const apiKeyId = row.data('id');
      $.ajax({
        type: 'POST',
        url: '/delete_api',
        data: { id: apiKeyId },
        success: (response) => {
          row.remove();
          displayMessage(response.success);
        },
        error: (xhr) => {
          const errorMessage = xhr.responseJSON ? xhr.responseJSON.error : "An error occurred";
          displayMessage(errorMessage, true);
        }
      });
    });
  });
  