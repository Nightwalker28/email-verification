function displayMessage(message, isError = false) {
    const messageContainer = $('#message-container');
    messageContainer.removeClass('d-none alert-success alert-danger');
    messageContainer.addClass('alert-danger');
    messageContainer.text(message);
    messageContainer.show();
    setTimeout(() => messageContainer.hide(), 5000);  // Hide message after 5 seconds
}

$(document).ready(function() {
    // Ensure the loading overlay is hidden initially
    $('#loadingOverlay').hide();

    // Handle Manual Email Verification
    $('#manualEmailForm').on('submit', function(event) {
        event.preventDefault();  // Prevent the form from submitting traditionally
        const emailAddress = $('#emailAddress').val();  // Get the email address from the input

        // Show the loading overlay
        $('#loadingOverlay').show();

        $.ajax({
            url: '/verify',
            type: 'POST',
            contentType: 'application/json',
            data: JSON.stringify({ email: emailAddress }),  // Send the email as JSON data
            success: function(response) {
                // Hide the loading overlay upon success
                $('#loadingOverlay').hide();
                // Display success message
                window.location.reload();
            },
            error: function(xhr) {
                // Hide the loading overlay in case of error
                $('#loadingOverlay').hide();
                // Display an error message if the request fails
                const errorMessage = xhr.responseJSON ? xhr.responseJSON.error : "An error occurred";
                displayMessage(errorMessage, true);
            }
        });
    });
    // Handle Force Email Verification
    $('#forceVerifyBtn').on('click', function() {
        let emailAddress = $('#emailAddress').val(); // Get the email address from the input

        // Show the loading overlay
        $('#loadingOverlay').show();

        // Make the AJAX request to force verify the email
        $.ajax({
            url: '/force-verify',
            type: 'POST',
            contentType: 'application/json',
            data: JSON.stringify({ email: emailAddress }), // Send the email as JSON data
            success: function(response) {
                // Hide the loading overlay upon success
                $('#loadingOverlay').hide();
                // Display success message
                window.location.reload();
            },
            error: function(xhr) {
                // Hide the loading overlay in case of error
                $('#loadingOverlay').hide();
                // Display an error message if the request fails
                const errorMessage = xhr.responseJSON ? xhr.responseJSON.error : "An error occurred";
                displayMessage(errorMessage, true);
            }
        });
    });
});
