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
          if (response.success === 'success') {
            displayMessage(response.message, false);
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

  // document.addEventListener("DOMContentLoaded", () => {
  //   const passwordInput = document.getElementById('password');
  //   const confirmPasswordInput = document.getElementById('confirm_password');
  //   const form = document.getElementById('form');
  //   const submitButton = form.querySelector('button[type="submit"]');
  
  //   const lengthRequirement = document.getElementById('length');
  //   const uppercaseRequirement = document.getElementById('uppercase');
  //   const lowercaseRequirement = document.getElementById('lowercase');
  //   const numberRequirement = document.getElementById('number');
  //   const specialCharRequirement = document.getElementById('specialChar');
  
  //   const lengthPattern = /^.{8,}$/;
  //   const uppercasePattern = /[A-Z]/;
  //   const lowercasePattern = /[a-z]/;
  //   const numberPattern = /\d/;
  //   const specialCharPattern = /[@$#!%*?&]/;
  
  //   const updateRequirement = (element, isValid) => {
  //     element.classList.toggle('valid', isValid);
  //     element.classList.toggle('invalid', !isValid);
  //   };
  
  //   const areAllRequirementsValid = (passwordValue) =>
  //     lengthPattern.test(passwordValue) &&
  //     uppercasePattern.test(passwordValue) &&
  //     lowercasePattern.test(passwordValue) &&
  //     numberPattern.test(passwordValue) &&
  //     specialCharPattern.test(passwordValue);
  
  //   const toggleSubmitButton = () => {
  //     const passwordValue = passwordInput.value;
  //     const allValid = areAllRequirementsValid(passwordValue);
  //     submitButton.disabled = !allValid;
  //   };
  
  //   passwordInput.addEventListener('input', () => {
  //     const passwordValue = passwordInput.value;
  //     updateRequirement(lengthRequirement, lengthPattern.test(passwordValue));
  //     updateRequirement(uppercaseRequirement, uppercasePattern.test(passwordValue));
  //     updateRequirement(lowercaseRequirement, lowercasePattern.test(passwordValue));
  //     updateRequirement(numberRequirement, numberPattern.test(passwordValue));
  //     updateRequirement(specialCharRequirement, specialCharPattern.test(passwordValue));
  //     toggleSubmitButton();
  //   });
  
  //   form.addEventListener('submit', (event) => {
  //     const passwordValue = passwordInput.value;
  //     const confirmPasswordValue = confirmPasswordInput.value;
  //     if (passwordValue !== confirmPasswordValue) {
  //       event.preventDefault();
  //       alert('Passwords do not match. Please try again.');
  //       return;
  //     }
  //     if (!areAllRequirementsValid(passwordValue)) {
  //       event.preventDefault();
  //       alert('Password must meet all the requirements.');
  //     }
  //   });
  
  //   toggleSubmitButton();
  // });
  
  