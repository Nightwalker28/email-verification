$(document).ready(function() {
$('a[href="/list"]').on('click', function(event) {
event.preventDefault();  // Prevent the default link behavior

// Show the loading overlay
$('#loadingOverlay').show();

// Make the AJAX request to check access to the list view
$.ajax({
    url: '/list',
    type: 'GET',
    success: function(response) {
        // If successful, redirect to the list page
        window.location.href = '/list';
    },
    error: function(xhr) {
        // Hide the loading overlay
        $('#loadingOverlay').hide();

        // Show the error message if access is restricted
        const errorMessage = xhr.responseJSON ? xhr.responseJSON.error : "An error occurred";
        displayMessage(errorMessage, true);  // Display the error in the on-screen container
    }
});
});
});