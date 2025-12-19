function displayMessage(message, isError = false) {
    const messageContainer = $('#message-container');
    messageContainer.removeClass('d-none alert-success alert-danger');
    messageContainer.addClass(isError ? 'alert-danger' : 'alert-success');
    messageContainer.text(message);
    messageContainer.show();
    
    if (!isError) {
        // Hide the message after 5 seconds if it's a success
        setTimeout(() => {
            messageContainer.hide();
            // Close the window after the message is hidden
            window.close(); // Attempt to close the window
        }, 5000);  // 5000 milliseconds = 5 seconds
    } else {
        // For error messages, just keep it until the user closes it or submits again
        setTimeout(() => messageContainer.hide(), 5000);  // Hide message after 5 seconds for errors as well
    }
}
$(document).ready(function() {
    $('#resetForm').on('submit', function(event) {
        event.preventDefault(); // Prevent the default form submission

        const password = $('#password').val();
        const token = $('input[name="token"]').val(); // Get the token from the hidden input

        // Send the password and token to the backend
        $.ajax({
            url: `/reset/${token}`,
            type: 'POST',
            contentType: 'application/json',
            data: JSON.stringify({ password: password }), // Send password as JSON
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