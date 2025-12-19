function displayMessage(message, isError = false) {
    const messageContainer = $('#message-container');
    messageContainer.removeClass('alert-success alert-danger');  // Reset classes
    messageContainer.addClass(isError ? 'alert-danger' : 'alert-success');  // Set correct class
    messageContainer.text(message);
    messageContainer.show();
    setTimeout(() => messageContainer.hide(), 5000);  // Hide message after 5 seconds
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