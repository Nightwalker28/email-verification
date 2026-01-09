function displayMessage(message, isError = false) {
    const messageContainer = $('#message-container');
    messageContainer.removeClass('d-none alert-success alert-danger');
    messageContainer.addClass(isError ? 'alert-danger' : 'alert-success');
    messageContainer.text(message);
    messageContainer.show();
    if (!isError) {
      setTimeout(() => {
        messageContainer.hide();
        window.close(); // Close window after success
      }, 5000);
    } else {
      setTimeout(() => messageContainer.hide(), 5000);
    }
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
  
    form.addEventListener('submit', (event) => {
      const passwordValue = passwordInput.value;
      const confirmPasswordValue = confirmPasswordInput.value;
      if (passwordValue !== confirmPasswordValue) {
        event.preventDefault();
        alert('Passwords do not match. Please try again.');
        return;
      }
      if (!areAllRequirementsValid(passwordValue)) {
        event.preventDefault();
        alert('Password must meet all the requirements.');
      }
    });
  
    toggleSubmitButton();
  });
  