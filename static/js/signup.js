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
  
  
  function setButtonLoading(isLoading) {
    const $submitButton = $('button[type="submit"]');
    
    if (isLoading) {
      
      $submitButton.data('original-text', $submitButton.text());
      $submitButton.prop('disabled', true);
      $submitButton.addClass('loading');
      $submitButton.html('<span class="spinner"></span>Signing Up...');
    } else {
      
      $submitButton.removeClass('loading');
      $submitButton.text($submitButton.data('original-text') || 'Sign Up');
      
      
      const password = $('#password').val();
      const confirmPassword = $('#confirm_password').val();
      const lengthValid = password.length >= 8;
      const uppercaseValid = /[A-Z]/.test(password);
      const lowercaseValid = /[a-z]/.test(password);
      const numberValid = /[0-9]/.test(password);
      const specialCharValid = /[@$!%*?&]/.test(password);
      const passwordsMatch = password === confirmPassword && password !== '';
      const allValid = lengthValid && uppercaseValid && lowercaseValid && numberValid && specialCharValid;
      
      $submitButton.prop('disabled', !(allValid && passwordsMatch));
    }
  }
  
  $(document).ready(() => {
    const $password = $('#password');
    const $confirmPassword = $('#confirm_password');
    const $submitButton = $('button[type="submit"]');
  
    
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
      
      
      if (!$submitButton.hasClass('loading')) {
        $submitButton.prop('disabled', !(allValid && passwordsMatch));
      }
    }
  
    $password.on('input', validatePassword);
    $confirmPassword.on('input', validatePassword);
  
    
    $('#form').on('submit', function(event) {
      event.preventDefault(); 
  
      
      setButtonLoading(true);
  
      const formData = $(this).serialize();
  
      $.ajax({
        type: 'POST',
        url: '/signup',  
        data: formData,
        success: function(response) {
          
          setButtonLoading(false);
          
          if (response.status === 'success') {
            displayMessage(response.message, false);
            
          } else {
            displayMessage("Unexpected response from server.", true);
          }
        },
        error: function(xhr) {
          
          setButtonLoading(false);
          
          const errorMessage =
            xhr.responseJSON && xhr.responseJSON.error 
              ? xhr.responseJSON.error 
              : "An error occurred during signup.";
          displayMessage(errorMessage, true);
        }
      });
    });
  });