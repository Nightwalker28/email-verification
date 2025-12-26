function displayMessage(message, isError = false) {
    const messageContainer = $('#message-container');
    messageContainer.removeClass('alert-success alert-danger d-none');
    messageContainer.addClass(isError ? 'alert-danger' : 'alert-success');
    messageContainer.text(message);
    messageContainer.show();
    setTimeout(() => messageContainer.addClass('d-none'), 5000);
  }
  
  $(document).ready(() => {
    $('#manual-signin-form').on('submit', function (event) {
      event.preventDefault();
      const formData = new FormData(this);
      $.ajax({
        url: '/manual_signin',
        type: 'POST',
        data: formData,
        contentType: false,
        processData: false,
        success: function (response) {
          if (response.redirect_url) {
            window.location.href = response.redirect_url;
          } else {
            displayMessage('Unexpected response, no redirect URL found.', true);
          }
        },
        error: function (xhr) {
          const errorMessage = xhr.responseJSON ? xhr.responseJSON.error : "An error occurred";
          displayMessage(errorMessage, true);
        }
      });
    });
  });
  