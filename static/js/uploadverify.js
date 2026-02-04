$(document).ready(function() {

    $('#deleteModal').hide();
    
    
    function formatFileSize(bytes) {
        if (bytes === 0) return '0 Bytes';
        const k = 1024;
        const sizes = ['Bytes', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    }

    
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

    
    function clearFileDisplay() {
        selectedFile = null;
        $('#file-name-display').text('No file selected');
        $('.file-size-display').text('');
        $('.file-upload-info').removeClass('show');
        $('.file-upload-wrapper').removeClass('has-file');
        $('.drag-drop-area').show();
        $('#csvFile').val('');
    }

    
    $('#csvFile').on('change', function() {
        const file = this.files && this.files[0] ? this.files[0] : null;
        updateFileDisplay(file);
        console.log('File selected:', file ? file.name : 'No file');
    });

    
    $(document).on('click', '.remove-file-btn', function(e) {
        e.preventDefault();
        e.stopPropagation();
        clearFileDisplay();
    });

    
    const $uploadWrapper = $('.file-upload-wrapper');

    
    $(document).on('dragenter dragover drop', function(e) {
        e.preventDefault();
        e.stopPropagation();
    });

    
    $uploadWrapper.on('dragenter', function(e) {
        e.preventDefault();
        e.stopPropagation();
        $(this).addClass('drag-over');
    });

    
    $uploadWrapper.on('dragover', function(e) {
        e.preventDefault();
        e.stopPropagation();
        $(this).addClass('drag-over');
    });

    
    $uploadWrapper.on('dragleave', function(e) {
        e.preventDefault();
        e.stopPropagation();
        
        if (!$(this).is(e.target) && !$.contains(this, e.target)) {
            $(this).removeClass('drag-over');
        }
    });

    
    $uploadWrapper.on('drop', function(e) {
        e.preventDefault();
        e.stopPropagation();
        $(this).removeClass('drag-over');

        const files = e.originalEvent.dataTransfer.files;
        if (files.length > 0) {
            const file = files[0];
            
            
            const allowedTypes = ['.csv', '.xlsx', '.xls'];
            const fileExtension = '.' + file.name.split('.').pop().toLowerCase();
            
            if (allowedTypes.includes(fileExtension)) {
                
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

    
    $uploadWrapper.on('click', function(e) {
        if (!$(e.target).hasClass('remove-file-btn') && !$(e.target).closest('.remove-file-btn').length) {
            $('#csvFile').click();
        }
    });

    
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

    
    function showLoading(message = "Processing...") {
        const loadingOverlay = $('#loadingOverlay');
        const loadingMessage = $('#loadingMessage');
        if (loadingMessage.length) {
            loadingMessage.text(message);
        }
        loadingOverlay.show();
    }

    
    function hideLoading() {
        $('#loadingOverlay').hide();
    }

    
    hideLoading();
    
    
    $('.toggle-details').on('click', function (e) {
        e.preventDefault();
        const id = $(this).data('id');
        const detailsRow = $(`#details-${id}`);
        detailsRow.toggleClass('show');
        $(this).toggleClass('open', detailsRow.hasClass('show'));
    });

    
    $('#verifyBtn').on('click', function(e) {
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

    
    $(document).on('click', '.delete-btn', function (e) {
        e.preventDefault();
        e.stopPropagation(); 
        
        console.log('Delete button clicked'); 
        
        deleteFormToSubmit = $(this).closest('form');
        
        
        $('#deleteModal').removeClass('d-none').show().css('display', 'flex');
        
        console.log('Modal should be visible now'); 
    });

    
    $('#confirmDeleteBtn').on('click', function () {
        console.log('Confirm delete clicked'); 
        
        if (deleteFormToSubmit) {
            
            $('#deleteModal').addClass('d-none').hide();
            
            
            const formAction = deleteFormToSubmit.attr('action');
            
            
            const rowToDelete = deleteFormToSubmit.closest('tr');
            const detailsRowId = rowToDelete.find('.toggle-details').data('id');
            const detailsRow = $(`#details-${detailsRowId}`);
            
            
            showLoading("Deleting file...");
            
            
            $.ajax({
                url: formAction,
                type: 'POST',
                success: function(response) {
                    hideLoading();
                    displayMessage('File deleted successfully!', false);
                    
                    
                    rowToDelete.fadeOut(300, function() {
                        $(this).remove();
                    });
                    
                    if (detailsRow.length) {
                        detailsRow.fadeOut(300, function() {
                            $(this).remove();
                        });
                    }
                    
                    
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
                    
                    const errorMessage = xhr.responseJSON ? xhr.responseJSON.error : "An error occurred while deleting the file";
                    displayMessage(errorMessage, true);
                }
            });
            
            deleteFormToSubmit = null;
        }
    });

    
    $('#cancelDeleteBtn').on('click', function () {
        console.log('Cancel delete clicked'); 
        
        deleteFormToSubmit = null;
        $('#deleteModal').addClass('d-none').hide();
    });

    
    $(document).on('click', '#deleteModal', function(e) {
        if (e.target === this) {
            deleteFormToSubmit = null;
            $('#deleteModal').addClass('d-none').hide();
        }
    });
    
});