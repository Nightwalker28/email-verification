$(document).ready(function() {
    // Handle CSV Upload
    $('#uploadForm').on('submit', function(event) {
        event.preventDefault();
        let formData = new FormData(this);

        $.ajax({
            url: '/upload',
            type: 'POST',
            data: formData,
            processData: false,
            contentType: false,
            success: function(response) {
                $('#downloadSection').show();
                $('#downloadLink').attr('href', '/download/' + response.filename);
            },
            error: function(xhr, status, error) {
                if (xhr.responseText) {
                    alert('Error: ' + xhr.responseText);
                } else {
                    console.error('Error:', error);
                }
            }
        });
    });

    // Handle Manual Email Verification
$('#manualEmailForm').on('submit', function(event) {
    event.preventDefault(); // Prevent the form from submitting normally

    let emailAddress = $('#emailAddress').val(); // Get the email address from the input

    // Hide the results and show a loading message
    $('#manualResult').hide().html('<strong>Loading...</strong>').show();

    // Make the AJAX request to verify the email
    $.ajax({
        url: '/verify',
        type: 'POST',
        contentType: 'application/json',
        data: JSON.stringify({ email: emailAddress }), // Send the email as JSON data
        success: function(response) {
            // Update the results section with the response data
            $('#manualResult').html(`
                <strong>Result:</strong> ${response.result}<br>
                <strong>Provider:</strong> ${response.provider}<br>
                <strong>Role Based:</strong> ${response.role_based}<br>
                <strong>Accept All?:</strong> ${response.accept_all}<br>
                <strong>Full Inbox?:</strong> ${response.full_inbox}<br>
            `).show(); // Show the results
        },
        error: function(xhr, status, error) {
            // Display an error message if the request fails
            $('#manualResult').html(`<strong>Error:</strong> ${xhr.responseText}`).show();
        }
    });
});

});
