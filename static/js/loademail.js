function displayMessage(message, isError = false) {
    const messageContainer = $('#message-container');
    messageContainer.removeClass('d-none alert-success alert-danger');
    messageContainer.addClass(isError ? 'alert-danger' : 'alert-success');
    messageContainer.text(message);
    messageContainer.show();
    setTimeout(() => messageContainer.hide(), 5000);
  }
  
  $(document).ready(() => {
    $('#passwrdForm').on('submit', function (event) {
      event.preventDefault();
      const emailAddress = $('#emailAddress').val();
      $.ajax({
        url: '/request_password_reset',
        type: 'POST',
        contentType: 'application/json',
        data: JSON.stringify({ emailAddress }),
        success: (response) => displayMessage(response.message, false),
        error: (xhr) => {
          const errorMessage = xhr.responseJSON ? xhr.responseJSON.error : "An error occurred";
          displayMessage(errorMessage, true);
        }
      });
    });
  });
  