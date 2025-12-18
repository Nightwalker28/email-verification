        function displayMessage(message, isError = false) {
            const messageContainer = $('#message-container');
            messageContainer.removeClass('d-none alert-success alert-danger');
            messageContainer.addClass(isError ? 'alert-danger' : 'alert-success');
            messageContainer.text(message);
            messageContainer.show();
            setTimeout(() => messageContainer.hide(), 5000);  // Hide message after 5 seconds
        }

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
                    window.location.reload();
                },
                error: function(xhr, status, error) {
                    const errorMessage = xhr.responseJSON ? xhr.responseJSON.error : "An error occurred";
                    displayMessage(errorMessage, true);
                }
            });
        });

        $('#forceVerifyBtn').on('click', function() {
            let formData = new FormData($('#uploadForm')[0]);
    
            $.ajax({
                url: '/force-upload',  // Force verification route
                type: 'POST',
                data: formData,
                contentType: false,
                processData: false,
                success: function(response) {
                    window.location.reload();
                },
                error: function(xhr, status, error) {
                    const errorMessage = xhr.responseJSON ? xhr.responseJSON.error : "An error occurred";
                    displayMessage(errorMessage, true);
                }
            });
        });

        $('.download-btn').on('click', function(e) {
            e.preventDefault();
        
            const uniqueFilename = $(this).data('filename'); // Retrieve unique filename for AJAX request
            const originalFilename = $(this).data('download_name'); // Retrieve original filename for download
        
            // Make an AJAX request to download the file
            $.ajax({
                url: `/download/${uniqueFilename}`, // Use unique filename in the URL
                type: 'GET',
                xhrFields: {
                    responseType: 'blob' // Set the response type to blob
                },
                success: function(blob) {
                    // Create a link element to trigger the download with the original filename
                    const url = window.URL.createObjectURL(blob);
                    const a = document.createElement('a');
                    a.href = url;
                    a.download = originalFilename; // Set the original filename for download
                    document.body.appendChild(a);
                    a.click(); // Trigger the download
                    a.remove(); // Remove the link from the document
                    window.URL.revokeObjectURL(url); // Clean up the URL object
                },
                error: function(xhr) {
                    // Display an error message if the request fails
                    const errorMessage = xhr.responseJSON ? xhr.responseJSON.error : "File Not Found";
                    displayMessage(errorMessage, true);
                }
            });
        });
        