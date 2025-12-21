function displayMessage(message, isError = false) {
    const messageContainer = $('#message-container');
    messageContainer.removeClass('d-none alert-success alert-danger');
    messageContainer.addClass(isError ? 'alert-danger' : 'alert-success');
    messageContainer.text(message);
    messageContainer.show();
    setTimeout(() => messageContainer.hide(), 5000);}

    $(document).ready(function () {
        const $password = $('#password');
        const $confirmPassword = $('#confirm_password');
        const $submitButton = $('button[type="submit"]');
    
        // Helper function to check password requirements
        function validatePassword() {
            const password = $password.val();
            const confirmPassword = $confirmPassword.val();
    
            // Define password criteria
            const lengthValid = password.length >= 8;
            const uppercaseValid = /[A-Z]/.test(password);
            const lowercaseValid = /[a-z]/.test(password);
            const numberValid = /[0-9]/.test(password);
            const specialCharValid = /[@$!%*?&]/.test(password);
    
            // Update checklist UI
            $('#length').toggleClass('valid', lengthValid).toggleClass('invalid', !lengthValid);
            $('#uppercase').toggleClass('valid', uppercaseValid).toggleClass('invalid', !uppercaseValid);
            $('#lowercase').toggleClass('valid', lowercaseValid).toggleClass('invalid', !lowercaseValid);
            $('#number').toggleClass('valid', numberValid).toggleClass('invalid', !numberValid);
            $('#specialChar').toggleClass('valid', specialCharValid).toggleClass('invalid', !specialCharValid);
    
            // Enable button only if all conditions are met and passwords match
            const passwordsMatch = password === confirmPassword && password !== '';
            const allConditionsMet = lengthValid && uppercaseValid && lowercaseValid && numberValid && specialCharValid;
            
            $submitButton.prop('disabled', !(allConditionsMet && passwordsMatch));
        }
    
        // Listen for input changes in password and confirm password fields
        $password.on('input', validatePassword);
        $confirmPassword.on('input', validatePassword);
    });
    