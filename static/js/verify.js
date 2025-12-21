$(document).ready(function() {
    // Ensure the loading overlay is hidden initially
    $('#loadingOverlay').hide();

    // Handle Manual Email Verification
    $('#manualEmailForm').on('submit', function(event) {
        event.preventDefault(); // Prevent the form from submitting normally

        let emailAddress = $('#emailAddress').val(); // Get the email address from the input

        // Show the loading overlay only when the form is submitted
        $('#loadingOverlay').show();

        // Make the AJAX request to verify the email
        $.ajax({
            url: '/verify',
            type: 'POST',
            contentType: 'application/json',
            data: JSON.stringify({ email: emailAddress }), // Send the email as JSON data
            success: function(response) {
                // Reload the page to update the last checked emails and reset verification attempts
                location.reload();
            },
            error: function(xhr, status, error) {
                // Hide the loading overlay in case of error
                $('#loadingOverlay').hide();
                // Display an error message if the request fails
                alert(`Error: ${xhr.responseText}`);
            }
        });
    });
});
