document.addEventListener("DOMContentLoaded", () => {
    const passwordInput = document.getElementById('password');
    const confirmPasswordInput = document.getElementById('confirm_password');
    const form = document.getElementById('form');
    const submitButton = form.querySelector('button[type="submit"]');
    const requirementsMessage = document.getElementById('requirementsMessage');
  
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
      const allValid = areAllRequirementsValid(passwordValue);
      submitButton.disabled = !allValid;
      requirementsMessage.style.display = allValid ? 'none' : 'block';
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
  
    form.addEventListener('submit', event => {
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
  