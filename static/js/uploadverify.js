$(document).ready(function() {

    $('#deleteModal').hide();
    
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
            messageContainer.addClass('show ' + (isError ? 'alert-danger' : 'alert-success'));
            messageContainer.text(message);
            messageContainer.show();
            setTimeout(() => {
                messageContainer.removeClass('show');
                messageContainer.hide();
            }, 5000);
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
        $(this).toggleClass('open', detailsRow.hasClass('show'));
    });

    // Handle normal file upload via verify button
    $('#verifyBtn').on('click', function(e) {
        e.preventDefault();
        const $btn = $(this);
        const $text = $btn.find('.button-text');
        const $spinner = $btn.find('.spinner');

        // Show spinner, hide text
        $text.hide();
        $spinner.show();

        const fileInput = $('#csvFile')[0];
        if (!fileInput.files || !fileInput.files[0]) {
            displayMessage("Please select a file to upload.", true);
            $spinner.hide();
            $text.show();
            return;
        }

        const formData = new FormData($('#uploadForm')[0]);
        showLoading("Uploading and verifying emails...");

        $.ajax({
            url: '/upload',
            type: 'POST',
            data: formData,
            contentType: false,
            processData: false,
            success: function(response) {
                hideLoading();
                displayMessage('File uploaded and verified successfully!', false);
                clearFileDisplay();
                $spinner.hide();
                $text.show();
                setTimeout(() => {
                    window.location.reload();
                }, 1500);
            },
            error: function(xhr) {
                hideLoading();
                const errorMessage = xhr.responseJSON ? xhr.responseJSON.error : "An error occurred";
                displayMessage(errorMessage, true);
                $spinner.hide();
                $text.show();
            }
        });
    });

    // Handle force file upload
    $('#forceVerifyBtn').on('click', function(e) {
        e.preventDefault();
        const $btn = $(this);
        const $text = $btn.find('.button-text');
        const $spinner = $btn.find('.spinner');

        $text.hide();
        $spinner.show();

        const fileInput = $('#csvFile')[0];
        if (!fileInput.files || !fileInput.files[0]) {
            displayMessage("Please select a file to upload.", true);
            $spinner.hide();
            $text.show();
            return;
        }

        const formData = new FormData($('#uploadForm')[0]);
        showLoading("Force verifying emails...");

        $.ajax({
            url: '/force-upload',
            type: 'POST',
            data: formData,
            contentType: false,
            processData: false,
            success: function(response) {
                hideLoading();
                displayMessage('File force verified successfully!', false);
                clearFileDisplay();
                $spinner.hide();
                $text.show();
                setTimeout(() => {
                    window.location.reload();
                }, 1500);
            },
            error: function(xhr) {
                hideLoading();
                const errorMessage = xhr.responseJSON ? xhr.responseJSON.error : "An error occurred";
                displayMessage(errorMessage, true);
                $spinner.hide();
                $text.show();
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

    let deleteFormToSubmit = null;

    // Show modal on delete click - FIXED EVENT DELEGATION
    $(document).on('click', '.delete-btn', function (e) {
        e.preventDefault();
        e.stopPropagation(); // Prevent event bubbling
        
        console.log('Delete button clicked'); // Debug log
        
        deleteFormToSubmit = $(this).closest('form');
        
        // Show modal using multiple methods to ensure visibility
        $('#deleteModal').removeClass('d-none').show().css('display', 'flex');
        
        console.log('Modal should be visible now'); // Debug log
    });

    // Confirm deletion - Remove row from DOM instead of refreshing
    $('#confirmDeleteBtn').on('click', function () {
        console.log('Confirm delete clicked'); // Debug log
        
        if (deleteFormToSubmit) {
            // Hide modal first
            $('#deleteModal').addClass('d-none').hide();
            
            // Get form action URL for the AJAX request
            const formAction = deleteFormToSubmit.attr('action');
            
            // Find the table row to remove (the form is inside the td)
            const rowToDelete = deleteFormToSubmit.closest('tr');
            const detailsRowId = rowToDelete.find('.toggle-details').data('id');
            const detailsRow = $(`#details-${detailsRowId}`);
            
            // Show loading
            showLoading("Deleting file...");
            
            // Submit via AJAX instead of form submission
            $.ajax({
                url: formAction,
                type: 'POST',
                success: function(response) {
                    hideLoading();
                    displayMessage('File deleted successfully!', false);
                    
                    // Remove both the main row and details row from the DOM
                    rowToDelete.fadeOut(300, function() {
                        $(this).remove();
                    });
                    
                    if (detailsRow.length) {
                        detailsRow.fadeOut(300, function() {
                            $(this).remove();
                        });
                    }
                    
                    // Check if table is now empty and show empty state
                    setTimeout(() => {
                        const remainingRows = $('.uploads-table tbody tr:not(.details-row)').length;
                        if (remainingRows === 0) {
                            $('.table-responsive').hide();
                            $('.uploads-section').append(`
                                <div class="empty-state">
                                    <svg xmlns="http://www.w3.org/2000/svg" width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="8" x2="12" y2="12"></line><line x1="12" y1="16" x2="12.01" y2="16"></line></svg>
                                    <p>No uploaded files found</p>
                                    <p class="empty-state-help">Upload a file to get started with batch verification</p>
                                </div>
                            `);
                        }
                    }, 400);
                },
                error: function(xhr) {
                    hideLoading();
                    // Show error alert
                    const errorMessage = xhr.responseJSON ? xhr.responseJSON.error : "An error occurred while deleting the file";
                    displayMessage(errorMessage, true);
                }
            });
            
            deleteFormToSubmit = null;
        }
    });

    // Cancel deletion
    $('#cancelDeleteBtn').on('click', function () {
        console.log('Cancel delete clicked'); // Debug log
        
        deleteFormToSubmit = null;
        $('#deleteModal').addClass('d-none').hide();
    });

    // Close modal when clicking outside of it
    $(document).on('click', '#deleteModal', function(e) {
        if (e.target === this) {
            deleteFormToSubmit = null;
            $('#deleteModal').addClass('d-none').hide();
        }
    });
    
});