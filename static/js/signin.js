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
  $('#manual-signin-form').on('submit', function (event) {
    event.preventDefault();
    const formData = new FormData(this);
    // Optional: Add a loading indicator here
    const $submitButton = $(this).find('button[type="submit"]');
    $submitButton.prop('disabled', true).text('Signing In...'); 
    $.ajax({
      url: '/manual_signin',
      type: 'POST',
      data: formData,
      contentType: false,
      processData: false,
      success: function (response) {
        if (response && response.status === 'success' && response.data && response.data.redirect_url) {
             window.location.href = response.data.redirect_url;
        } else {
          const msg = response.message || 'Unexpected response format from server.';
          displayMessage(msg, true);
        }
      },
      error: function (xhr) {
        const errorMessage = (xhr.responseJSON && xhr.responseJSON.error)
                             ? xhr.responseJSON.error 
                             : "An unknown error occurred during sign in.";
        displayMessage(errorMessage, true);
      },
      complete: function() {
        $submitButton.prop('disabled', false).text('Sign In'); 
      }
    });
  });
});
