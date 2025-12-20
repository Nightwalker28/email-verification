function displayMessage(message, isError = false) {
    const messageContainer = $('#message-container');
    // Reset classes and visibility
    messageContainer.removeClass('alert-success alert-danger d-none');  // Reset classes and remove hidden class
    // Set the appropriate class based on error status
    messageContainer.addClass(isError ? 'alert-danger' : 'alert-success');
    // Set the message text
    messageContainer.text(message);
    // Show the message container
    messageContainer.show();
    // Hide the message after 5 seconds
    setTimeout(() => {
        messageContainer.addClass('d-none');  // Hide the message container after 5 seconds
    }, 5000);
}

$(document).ready(function() {
    $('#manual-signin-form').on('submit', function(event) {
        event.preventDefault();  // Prevent traditional form submission
        const formData = new FormData(this);
        $.ajax({
            url: '/manual_signin',
            type: 'POST',
            data: formData,
            contentType: false,
            processData: false,
            success: function(response) {
                // Check if the redirect_url exists in the response
                if (response.redirect_url) {
                    window.location.href = response.redirect_url;
                } else {
                    displayMessage('Unexpected response, no redirect URL found.', true);
                }
            },
            error: function(xhr, status, error) {
                const errorMessage = xhr.responseJSON ? xhr.responseJSON.error : "An error occurred";
                displayMessage(errorMessage, true);
            }
        });
    });
});