$(document).ready(function() {
    $('#uploadForm').on('submit', function(event) {
        event.preventDefault();
        let formData = new FormData(this);
        
        $.ajax({
            url: '/upload',  // Normal verification route
            type: 'POST',
            data: formData,
            contentType: false,
            processData: false,
            success: function(response) {
                location.reload();
            },
            error: function(xhr, status, error) {
                alert(`Error: ${xhr.responseText}`);
            }
        });
    });

    // Handle force verification for the list
    $('#forceVerifyBtn').on('click', function() {
        let formData = new FormData($('#uploadForm')[0]);

        $.ajax({
            url: '/force-upload',  // Force verification route
            type: 'POST',
            data: formData,
            contentType: false,
            processData: false,
            success: function(response) {
                location.reload();
            },
            error: function(xhr, status, error) {
                alert(`Error: ${xhr.responseText}`);
            }
        });
    });
});
