$(document).ready(function() {
    // Update file name display when a file is selected
    $('#csvFile').on('change', function() {
        const fileName = this.files && this.files[0] ? this.files[0].name : 'No file selected';
        $('#file-name-display').text(fileName);
        console.log('File selected:', fileName);
    });

    // Utility to display messages
    function displayMessage(message, isError = false) {
        const messageContainer = $('#message-container');
        if (messageContainer.length) {
            messageContainer.removeClass('d-none alert-success alert-danger');
            messageContainer.addClass(isError ? 'alert-danger' : 'alert-success');
            messageContainer.text(message);
            messageContainer.show();
            setTimeout(() => messageContainer.hide(), 5000);
        } else {
            alert(message);
        }
    }

    // Show loading overlay
    function showLoading(message = "Processing...") {
        const loadingOverlay = $('#loadingOverlay');
        const loadingMessage = $('#loadingMessage');
        if (loadingMessage.length) {
            loadingMessage.text(message);
        }
        loadingOverlay.show();
    }

    // Hide loading overlay
    function hideLoading() {
        $('#loadingOverlay').hide();
    }

    // Hide the loading overlay initially
    hideLoading();
    
    // Toggle additional details for a given record
    $('.toggle-details').on('click', function (e) {
        e.preventDefault();
        const id = $(this).data('id');
        const detailsRow = $(`#details-${id}`);
        detailsRow.toggleClass('show');
    });

    // Handle normal file upload via verify button
    $('#verifyBtn').on('click', function(e) {
        e.preventDefault();
        
        const fileInput = $('#csvFile')[0];
        console.log('File input:', fileInput);
        console.log('Files:', fileInput.files);
        
        if (!fileInput.files || !fileInput.files[0]) {
            displayMessage("Please select a file to upload.", true);
            return;
        }
        
        console.log('Selected file:', fileInput.files[0].name);
        
        const formData = new FormData($('#uploadForm')[0]);
        showLoading("Uploading and verifying emails...");
        
        $.ajax({
            url: '/upload',
            type: 'POST',
            data: formData,
            contentType: false,
            processData: false,
            success: function() {
                hideLoading();
                window.location.reload();
            },
            error: function(xhr) {
                hideLoading();
                const errorMessage = xhr.responseJSON ? xhr.responseJSON.error : "An error occurred";
                displayMessage(errorMessage, true);
            }
        });
    });

    // Handle force file upload
    $('#forceVerifyBtn').on('click', function(e) {
        e.preventDefault();
        
        const fileInput = $('#csvFile')[0];
        console.log('Force verify - File input:', fileInput);
        console.log('Force verify - Files:', fileInput.files);
        
        if (!fileInput.files || !fileInput.files[0]) {
            displayMessage("Please select a file to upload.", true);
            return;
        }
        
        console.log('Force verify - Selected file:', fileInput.files[0].name);
        
        const formData = new FormData($('#uploadForm')[0]);
        showLoading("Force verifying emails...");
        
        $.ajax({
            url: '/force-upload',
            type: 'POST',
            data: formData,
            contentType: false,
            processData: false,
            success: function() {
                hideLoading();
                window.location.reload();
            },
            error: function(xhr) {
                hideLoading();
                const errorMessage = xhr.responseJSON ? xhr.responseJSON.error : "An error occurred";
                displayMessage(errorMessage, true);
            }
        });
    });

    // Handle file download with AJAX and blob response
    $('.download-btn').on('click', function (e) {
        e.preventDefault();
        const uniqueFilename = $(this).data('filename');
        const originalFilename = $(this).data('download_name');
        
        showLoading("Downloading file...");
        
        $.ajax({
            url: `/download/${uniqueFilename}`,
            type: 'GET',
            xhrFields: { responseType: 'blob' },
            success: function(blob) {
                hideLoading();
                const url = window.URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = originalFilename;
                document.body.appendChild(a);
                a.click();
                a.remove();
                window.URL.revokeObjectURL(url);
            },
            error: function(xhr) {
                hideLoading();
                const errorMessage = xhr.responseJSON ? xhr.responseJSON.error : "File Not Found";
                displayMessage(errorMessage, true);
            }
        });
    });
});