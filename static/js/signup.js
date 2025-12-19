function displayMessage(message, isError = false) {
    const messageContainer = $('#message-container');
    messageContainer.removeClass('d-none alert-success alert-danger');
    messageContainer.addClass(isError ? 'alert-danger' : 'alert-success');
    messageContainer.text(message);
    messageContainer.show();
    setTimeout(() => messageContainer.hide(), 5000);}

$(document).ready(function() {
    $('#signup-form').on('submit', function(event) {
        event.preventDefault();  // Prevent traditional form submission
        const formData = new FormData(this);

        $.ajax({
            url: '/signup',
            type: 'POST',
            data: formData,
            contentType: 'application/json',
            processData: false,
            success: function(response) {
                displayMessage(response.success, false);
            },
            error: function(xhr) {
                const errorMessage = xhr.responseJSON ? xhr.responseJSON.error : "An error occurred";
                displayMessage(errorMessage, true);
            }
        });
    });
    });
