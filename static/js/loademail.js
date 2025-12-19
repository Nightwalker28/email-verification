
function displayMessage(message, isError = false) {
    const messageContainer = $('#message-container');
    messageContainer.removeClass('d-none alert-success alert-danger');
    if (isError) {
        messageContainer.addClass('alert-danger').removeClass('alert-success');
    } else {
        messageContainer.addClass('alert-success').removeClass('alert-danger');
    }
    messageContainer.text(message);
    messageContainer.show();
    setTimeout(() => messageContainer.hide(), 5000);  // Hide message after 5 seconds
}

$(document).ready(function() {
    $('#passwrdForm').on('submit', function(event) {
        event.preventDefault();  // Prevent form submission
        const emailAddress = $('#emailAddress').val(); // Get the email from the input

        // Send the email to the backend
        $.ajax({
            url: '/request_password_reset',
            type: 'POST',
                    contentType: 'application/json',
                    data: JSON.stringify({ emailAddress: emailAddress }), // Send email as JSON
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

