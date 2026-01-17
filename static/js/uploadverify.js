$(document).ready(function() {
    let selectedFile = null;

    // Utility function to format file size
    function formatFileSize(bytes) {
        if (bytes === 0) return '0 Bytes';
        const k = 1024;
        const sizes = ['Bytes', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    }

    // Update file display
    function updateFileDisplay(file) {
        selectedFile = file;
        if (file) {
            $('#file-name-display').text(file.name);
            $('.file-size-display').text(formatFileSize(file.size));
            $('.file-upload-info').addClass('show');
            $('.file-upload-wrapper').addClass('has-file');
            $('.drag-drop-area').hide();
        } else {
            clearFileDisplay();
        }
    }

    // Clear file display
    function clearFileDisplay() {
        selectedFile = null;
        $('#file-name-display').text('No file selected');
        $('.file-size-display').text('');
        $('.file-upload-info').removeClass('show');
        $('.file-upload-wrapper').removeClass('has-file');
        $('.drag-drop-area').show();
        $('#csvFile').val('');
    }

    // Handle file input change
    $('#csvFile').on('change', function() {
        const file = this.files && this.files[0] ? this.files[0] : null;
        updateFileDisplay(file);
        console.log('File selected:', file ? file.name : 'No file');
    });

    // Remove file button
    $(document).on('click', '.remove-file-btn', function(e) {
        e.preventDefault();
        e.stopPropagation();
        clearFileDisplay();
    });

    // Drag and drop functionality
    const $uploadWrapper = $('.file-upload-wrapper');

    // Prevent default drag behaviors
    $(document).on('dragenter dragover drop', function(e) {
        e.preventDefault();
        e.stopPropagation();
    });

    // Drag enter
    $uploadWrapper.on('dragenter', function(e) {
        e.preventDefault();
        e.stopPropagation();
        $(this).addClass('drag-over');
    });

    // Drag over
    $uploadWrapper.on('dragover', function(e) {
        e.preventDefault();
        e.stopPropagation();
        $(this).addClass('drag-over');
    });

    // Drag leave
    $uploadWrapper.on('dragleave', function(e) {
        e.preventDefault();
        e.stopPropagation();
        // Only remove drag-over if we're actually leaving the wrapper
        if (!$(this).is(e.target) && !$.contains(this, e.target)) {
            $(this).removeClass('drag-over');
        }
    });

    // Drop
    $uploadWrapper.on('drop', function(e) {
        e.preventDefault();
        e.stopPropagation();
        $(this).removeClass('drag-over');

        const files = e.originalEvent.dataTransfer.files;
        if (files.length > 0) {
            const file = files[0];
            
            // Validate file type
            const allowedTypes = ['.csv', '.xlsx', '.xls'];
            const fileExtension = '.' + file.name.split('.').pop().toLowerCase();
            
            if (allowedTypes.includes(fileExtension)) {
                // Update the file input
                const dataTransfer = new DataTransfer();
                dataTransfer.items.add(file);
                $('#csvFile')[0].files = dataTransfer.files;
                
                updateFileDisplay(file);
                console.log('File dropped:', file.name);
            } else {
                displayMessage('Please select a valid file format (.csv, .xlsx, .xls)', true);
            }
        }
    });

    // Click to select file
    $uploadWrapper.on('click', function(e) {
        if (!$(e.target).hasClass('remove-file-btn') && !$(e.target).closest('.remove-file-btn').length) {
            $('#csvFile').click();
        }
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