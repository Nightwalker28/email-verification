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
  
  document.addEventListener("DOMContentLoaded", () => {
    const passwordInput = document.getElementById('password');
    const confirmPasswordInput = document.getElementById('confirm_password');
    const form = document.getElementById('form');
    const submitButton = form.querySelector('button[type="submit"]');
  
    const lengthRequirement = document.getElementById('length');
    const uppercaseRequirement = document.getElementById('uppercase');
    const lowercaseRequirement = document.getElementById('lowercase');
    const numberRequirement = document.getElementById('number');
    const specialCharRequirement = document.getElementById('specialChar');
  
    const lengthPattern = /^.{8,}$/;
    const uppercasePattern = /[A-Z]/;
    const lowercasePattern = /[a-z]/;
    const numberPattern = /\d/;
    const specialCharPattern = /[@$#!%*?&]/;
  
    const updateRequirement = (element, isValid) => {
      element.classList.toggle('valid', isValid);
      element.classList.toggle('invalid', !isValid);
    };
  
    const areAllRequirementsValid = (passwordValue) =>
      lengthPattern.test(passwordValue) &&
      uppercasePattern.test(passwordValue) &&
      lowercasePattern.test(passwordValue) &&
      numberPattern.test(passwordValue) &&
      specialCharPattern.test(passwordValue);
  
    const toggleSubmitButton = () => {
      const passwordValue = passwordInput.value;
      const confirmPasswordValue = confirmPasswordInput.value;
      const allValid = areAllRequirementsValid(passwordValue) && passwordValue === confirmPasswordValue;
      submitButton.disabled = !allValid;
    };
  
    passwordInput.addEventListener('input', () => {
      const passwordValue = passwordInput.value;
      updateRequirement(lengthRequirement, lengthPattern.test(passwordValue));
      updateRequirement(uppercaseRequirement, uppercasePattern.test(passwordValue));
      updateRequirement(lowercaseRequirement, lowercasePattern.test(passwordValue));
      updateRequirement(numberRequirement, numberPattern.test(passwordValue));
      updateRequirement(specialCharRequirement, specialCharPattern.test(passwordValue));
      toggleSubmitButton();
    });
  
    confirmPasswordInput.addEventListener('input', toggleSubmitButton);

    form.addEventListener('submit', function(event) {
      event.preventDefault();

      const passwordValue = passwordInput.value;
      const confirmPasswordValue = confirmPasswordInput.value;

      if (passwordValue !== confirmPasswordValue) {
        displayMessage('Passwords do not match. Please try again.', true);
        return;
      }
      if (!areAllRequirementsValid(passwordValue)) {
        displayMessage('Password must meet all the requirements.', true);
        return;
      }

      submitButton.disabled = true;
      submitButton.classList.add('loading');
      const originalText = submitButton.innerHTML;
      submitButton.innerHTML = '<span class="spinner"></span> Resetting...';

      const formData = new FormData(form);

      $.ajax({
        url: form.action,
        type: 'POST',
        data: formData,
        processData: false,
        contentType: false,
        dataType: 'html',
        success: function(response) {
          displayMessage('Password updated successfully!');
          setTimeout(() => {
            submitButton.classList.remove('loading');
            submitButton.innerHTML = originalText;
            submitButton.disabled = false;
          }, 4000);
        },
        error: function(xhr) {
          let errorMsg = xhr.responseText || 'An error occurred. Please try again.';
          displayMessage(errorMsg, true);
          submitButton.classList.remove('loading');
          submitButton.innerHTML = originalText;
          submitButton.disabled = false;
        }
      });
    });
  
    toggleSubmitButton();
  });
  