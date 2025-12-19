document.addEventListener("DOMContentLoaded", () => {
    const passwordInput = document.getElementById('password');
    const confirmPasswordInput = document.getElementById('confirm_password');
    const form = document.getElementById('form');
    const submitButton = form.querySelector('button[type="submit"]');
    const requirementsMessage = document.createElement('div');

    // Password requirements elements
    const lengthRequirement = document.getElementById('length');
    const uppercaseRequirement = document.getElementById('uppercase');
    const lowercaseRequirement = document.getElementById('lowercase');
    const numberRequirement = document.getElementById('number');
    const specialCharRequirement = document.getElementById('specialChar');

    // Regular expressions
    const lengthPattern = /^.{8,}$/;
    const uppercasePattern = /[A-Z]/;
    const lowercasePattern = /[a-z]/;
    const numberPattern = /\d/;
    const specialCharPattern = /[@$#!%*?&]/;

    // Update requirement status
    function updateRequirement(element, isValid) {
        if (isValid) {
            element.classList.add('valid');
            element.classList.remove('invalid');
        } else {
            element.classList.add('invalid');
            element.classList.remove('valid');
        }
    }

    // Check if all requirements are valid
    function areAllRequirementsValid(passwordValue) {
        return lengthPattern.test(passwordValue) &&
            uppercasePattern.test(passwordValue) &&
            lowercasePattern.test(passwordValue) &&
            numberPattern.test(passwordValue) &&
            specialCharPattern.test(passwordValue);
    }

    // Disable/enable the submit button based on requirements
    function toggleSubmitButton() {
        const passwordValue = passwordInput.value;
        const allValid = areAllRequirementsValid(passwordValue);
        submitButton.disabled = !allValid;

        // Show or hide the requirements message
        if (!allValid) {
            requirementsMessage.style.display = 'block';
        } else {
            requirementsMessage.style.display = 'none';
        }
    }

    // Check the password as the user types
    passwordInput.addEventListener('input', () => {
        const passwordValue = passwordInput.value;

        updateRequirement(lengthRequirement, lengthPattern.test(passwordValue));
        updateRequirement(uppercaseRequirement, uppercasePattern.test(passwordValue));
        updateRequirement(lowercaseRequirement, lowercasePattern.test(passwordValue));
        updateRequirement(numberRequirement, numberPattern.test(passwordValue));
        updateRequirement(specialCharRequirement, specialCharPattern.test(passwordValue));

        // Toggle the submit button based on requirements
        toggleSubmitButton();
    });

    // Validate form on submission
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

    // Initially disable the submit button
    toggleSubmitButton();
});
