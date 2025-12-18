function displayMessage(message, isError = false) {
    const messageContainer = $('#message-container');
    messageContainer.removeClass('alert-success alert-danger');  // Reset classes
    messageContainer.addClass(isError ? 'alert-danger' : 'alert-success');  // Set correct class
    messageContainer.text(message);
    messageContainer.show();
    setTimeout(() => messageContainer.hide(), 5000);  // Hide message after 5 seconds
}

$(document).ready(function() {
    $('#signup-form').on('submit', function(event) {
        event.preventDefault();  // Prevent traditional form submission
        const formData = new FormData(this);

        $.ajax({
            url: '/signup',
            type: 'POST',
            data: formData,
            contentType: false,
            processData: false,
            success: function(response) {
                displayMessage(response.success, false);  // Display success message
            },
            error: function(xhr) {
                const errorMessage = xhr.responseJSON ? xhr.responseJSON.error : "An error occurred";
                displayMessage(errorMessage, true);  // Display error message
            }
        });
    });
});
