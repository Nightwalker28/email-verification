function displayMessage(message, isError = false) {
    const messageContainer = $('#message-container');
    messageContainer.removeClass('d-none alert-success alert-danger');
    messageContainer.addClass(isError ? 'alert-danger' : 'alert-success');
    messageContainer.text(message);
    messageContainer.show();
    setTimeout(() => messageContainer.hide(), 5000);
  }
  
  $(document).ready(() => {
    const $password = $('#password');
    const $confirmPassword = $('#confirm_password');
    const $submitButton = $('button[type="submit"]');
  
    // Validate password requirements in real-time
    function validatePassword() {
      const password = $password.val();
      const confirmPassword = $confirmPassword.val();
      const lengthValid = password.length >= 8;
      const uppercaseValid = /[A-Z]/.test(password);
      const lowercaseValid = /[a-z]/.test(password);
      const numberValid = /[0-9]/.test(password);
      const specialCharValid = /[@$!%*?&]/.test(password);
  
      $('#length').toggleClass('valid', lengthValid).toggleClass('invalid', !lengthValid);
      $('#uppercase').toggleClass('valid', uppercaseValid).toggleClass('invalid', !uppercaseValid);
      $('#lowercase').toggleClass('valid', lowercaseValid).toggleClass('invalid', !lowercaseValid);
      $('#number').toggleClass('valid', numberValid).toggleClass('invalid', !numberValid);
      $('#specialChar').toggleClass('valid', specialCharValid).toggleClass('invalid', !specialCharValid);
  
      const passwordsMatch = password === confirmPassword && password !== '';
      const allValid = lengthValid && uppercaseValid && lowercaseValid && numberValid && specialCharValid;
      $submitButton.prop('disabled', !(allValid && passwordsMatch));
    }
  
    $password.on('input', validatePassword);
    $confirmPassword.on('input', validatePassword);
  
    // Intercept form submission and send signup data via AJAX
    $('#form').on('submit', function(event) {
      event.preventDefault(); // Prevent the default form submission
  
      const formData = $(this).serialize();
  
      $.ajax({
        type: 'POST',
        url: '/signup',  // Your backend signup route
        data: formData,
        success: function(response) {
          if (response.success) {
            displayMessage(response.success, false);
            // Optionally, redirect after a short delay:
          } else {
            displayMessage("Unexpected response from server.", true);
          }
        },
        error: function(xhr) {
          const errorMessage =
            xhr.responseJSON && xhr.responseJSON.error 
              ? xhr.responseJSON.error 
              : "An error occurred during signup.";
          displayMessage(errorMessage, true);
        }
      });
    });
  });
  