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
      success: (response, status, xhr) => {
        $('#loadingOverlay').hide();
  
        // Check if this is a silent HTML redirect (Flask sending the pricing page)
        if (
          typeof response === "string" &&
          response.includes('<title>Pricing') // or any unique element on the pricing page
        ) {
          window.location.href = '/pricing';
          return;
        }
  
        // Normal success path
        window.location.reload();
      },
      error: (xhr) => {
        $('#loadingOverlay').hide();
  
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
  