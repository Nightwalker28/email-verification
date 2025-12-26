// Utility to display messages; uses alert-success for normal and alert-danger for errors.
const displayMessage = (message, isError = false) => {
    const messageContainer = $('#message-container');
    messageContainer.removeClass('d-none alert-success alert-danger');
    messageContainer.addClass(isError ? 'alert-danger' : 'alert-success');
    messageContainer.text(message);
    messageContainer.show();
    setTimeout(() => messageContainer.hide(), 5000);
  };
  
  // Helper function to perform email verification via AJAX.
  const performVerification = (url, emailAddress) => {
    $('#loadingOverlay').show();
    $.ajax({
      url: url,
      type: 'POST',
      contentType: 'application/json',
      data: JSON.stringify({ email: emailAddress }),
      success: () => {
        $('#loadingOverlay').hide();
        window.location.reload();
      },
      error: (xhr) => {
        $('#loadingOverlay').hide();
        const errorMessage = xhr.responseJSON ? xhr.responseJSON.error : "An error occurred";
        displayMessage(errorMessage, true);
      }
    });
  };
  
  $(document).ready(() => {
    // Hide the loading overlay initially.
    $('#loadingOverlay').hide();
  
    // Handle manual verification
    $('#manualEmailForm').on('submit', (event) => {
      event.preventDefault();
      const emailAddress = $('#emailAddress').val();
      performVerification('/verify', emailAddress);
    });
  
    // Handle forced verification
    $('#forceVerifyBtn').on('click', () => {
      const emailAddress = $('#emailAddress').val();
      performVerification('/force-verify', emailAddress);
    });
  });
  