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
  
  $(document).ready(() => {
    const $resetBtn = $('#resetBtn');
    const originalBtnHtml = $resetBtn.html();

    $('#passwrdForm').on('submit', function (event) {
      event.preventDefault();
      const emailAddress = $('#emailAddress').val();

      
      $resetBtn.prop('disabled', true);
      $resetBtn.html('<span class="spinner"></span> Sending...');

      $.ajax({
        url: '/request_password_reset',
        type: 'POST',
        contentType: 'application/json',
        data: JSON.stringify({ emailAddress }),

        success: (response) => {
          displayMessage(response.message, false),
          $resetBtn.prop('disabled', false);
          $resetBtn.html(originalBtnHtml);
        },

        error: (xhr) => {
          const errorMessage = xhr.responseJSON ? xhr.responseJSON.error : "An error occurred";
          displayMessage(errorMessage, true);
          $resetBtn.prop('disabled', false);
          $resetBtn.html(originalBtnHtml);
        }
      });
    });
  });
  