    function displayMessage(message, isError = false) {
        const messageContainer = $('#message-container');
        messageContainer.removeClass('d-none alert-success alert-danger');
        messageContainer.addClass(isError ? 'alert-danger' : 'alert-success');
        messageContainer.text(message);
        messageContainer.show();
        setTimeout(() => messageContainer.hide(), 5000);  // Hide message after 5 seconds
    }
    function validateForm(event) {
        // Get the password and confirm password values
        const password = document.getElementById('password').value;
        const confirmPassword = document.getElementById('confirm_password').value;

        // Regular expression for a strong password: 
        // At least 8 characters, at least one uppercase letter, one lowercase letter, one number, and one special character
        const passwordPattern = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/;

        // Check if passwords match
        if (password !== confirmPassword) {
            event.preventDefault();
            alert('Passwords do not match. Please try again.');
            return;
        }

        // Check if password is strong
        if (password && !passwordPattern.test(password)) {
            event.preventDefault();
            alert('Password must be at least 8 characters long and include at least one uppercase letter, one lowercase letter, one number, and one special character.');
            return;
        }
    }

    $(document).ready(function() {
        $('form').on('submit', function(event) {
            event.preventDefault(); // Prevent the default form submission
            
            validateForm(event); // Validate the form before proceeding
            
            const formData = {
                first_name: $('#first_name').val(),
                last_name: $('#last_name').val(),
                password: $('#password').val() // Include password if provided
            };

            // Send the AJAX request
            $.ajax({
                url: '/profile',
                type: 'POST',
                contentType: 'application/json',
                data: JSON.stringify(formData),
                success: function(response) {
                    // Access the 'success' key instead of 'message'
                    displayMessage(response.success, false);
                },
                error: function(xhr) {
                    const errorMessage = xhr.responseJSON ? xhr.responseJSON.error : "An error occurred";
                    displayMessage(errorMessage, true);
                }
            });
        });
    });