// Update file name display when a file is selected
    document.getElementById('csvFile').addEventListener('change', function() {
        const fileName = this.files[0] ? this.files[0].name : 'No file selected';
        document.getElementById('file-name-display').textContent = fileName;
    });

    // Toggle details rows
    document.addEventListener('DOMContentLoaded', function() {
        const toggleButtons = document.querySelectorAll('.toggle-details');
        toggleButtons.forEach(button => {
            button.addEventListener('click', function(e) {
                e.preventDefault();
                const id = this.getAttribute('data-id');
                const detailsRow = document.getElementById('details-' + id);
                detailsRow.classList.toggle('show');
            });
        });
        
        // Handle verify button click (in case uploadverify.js doesn't handle it)
        document.getElementById('verifyBtn').addEventListener('click', function() {
            const form = document.getElementById('uploadForm');
            const formData = new FormData(form);
            
            $.ajax({
                url: '/upload',  // Update this to match your endpoint
                type: 'POST',
                data: formData,
                processData: false,
                contentType: false,
                success: function(response) {
                    window.location.reload();
                },
                error: function(error) {
                    console.error('Error uploading file:', error);
                    alert('There was an error uploading your file. Please try again.');
                }
            });
        });
    });

// Utility to display messages; uses alert-success for normal and alert-danger for errors.
const displayMessage = (message, isError = false) => {
  const messageContainer = $('#message-container');
  messageContainer.removeClass('d-none alert-success alert-danger');
  messageContainer.addClass(isError ? 'alert-danger' : 'alert-success');
  messageContainer.text(message);
  messageContainer.show();
  setTimeout(() => messageContainer.hide(), 5000);
};

// Show loading overlay
const showLoading = (message = "Processing...") => {
  const loadingOverlay = $('#loadingOverlay');
  // Add loading message if it exists
  const loadingMessage = $('#loadingMessage');
  if (loadingMessage.length) {
    loadingMessage.text(message);
  }
  loadingOverlay.addClass('active');
  loadingOverlay.show();
};

// Hide loading overlay
const hideLoading = () => {
  const loadingOverlay = $('#loadingOverlay');
  loadingOverlay.removeClass('active');
  loadingOverlay.hide();
};

// Check verification status of a file
const checkVerificationStatus = (uniqueFilename, callback) => {
  $.ajax({
    url: `/verification-status/${uniqueFilename}`,
    type: 'GET',
    success: (response) => {
      if (response.status === 'completed') {
        callback(true);
      } else {
        // If still in progress, check again after a delay
        setTimeout(() => checkVerificationStatus(uniqueFilename, callback), 2000);
      }
    },
    error: (xhr) => {
      // In case of error, assume it's done to prevent infinite loop
      callback(false);
      const errorMessage = xhr.responseJSON ? xhr.responseJSON.error : "Error checking verification status";
      displayMessage(errorMessage, true);
    }
  });
};

$(document).ready(() => {
  // Hide the loading overlay initially
  $('#loadingOverlay').hide();
  
  // Toggle additional details for a given record.
  $('.toggle-details').on('click', function (e) {
    e.preventDefault();
    const id = $(this).data('id');
    const detailsRow = $(`#details-${id}`);
    if (detailsRow.length) {
      detailsRow.toggle();
    } else {
      console.log(`Details row not found for ID: ${id}`);
    }
  });

  // Handle normal file upload.
  $('#verifyBtn').on('click', () => {
    const formData = new FormData($('#uploadForm')[0]);
    showLoading("Uploading and verifying emails...");
    $.ajax({
      url: '/upload',
      type: 'POST',
      data: formData,
      contentType: false,
      processData: false,
      success: (response) => {
        if (response.status === 'processing' && response.uniqueFilename) {
          // File uploaded, but verification is still in progress
          showLoading("Verifying emails... This may take a moment.");
          checkVerificationStatus(response.uniqueFilename, (success) => {
            hideLoading();
            window.location.reload();
          });
        } else {
          // Verification completed immediately
          hideLoading();
          window.location.reload();
        }
      },
      error: (xhr) => {
        hideLoading();
        const errorMessage = xhr.responseJSON ? xhr.responseJSON.error : "An error occurred";
        displayMessage(errorMessage, true);
      }
    });
  });

  // Handle force file upload.
  $('#forceVerifyBtn').on('click', () => {
    const formData = new FormData($('#uploadForm')[0]);
    showLoading("Force verifying emails...");
    $.ajax({
      url: '/force-upload',
      type: 'POST',
      data: formData,
      contentType: false,
      processData: false,
      success: (response) => {
        if (response.status === 'processing' && response.uniqueFilename) {
          // File uploaded, but verification is still in progress
          showLoading("Force verifying emails... This may take a moment.");
          checkVerificationStatus(response.uniqueFilename, (success) => {
            hideLoading();
            window.location.reload();
          });
        } else {
          // Verification completed immediately
          hideLoading();
          window.location.reload();
        }
      },
      error: (xhr) => {
        hideLoading();
        const errorMessage = xhr.responseJSON ? xhr.responseJSON.error : "An error occurred";
        displayMessage(errorMessage, true);
      }
    });
  });

  // Handle file view with loading for verification status
  $('.view-btn').on('click', function(e) {
    const uniqueFilename = $(this).attr('href').split('/').pop();
    $.ajax({
      url: `/verification-status/${uniqueFilename}`,
      type: 'GET',
      success: (response) => {
        if (response.status === 'processing') {
          e.preventDefault(); // Prevent navigation
          showLoading("Verification in progress... Please wait.");
          checkVerificationStatus(uniqueFilename, (success) => {
            hideLoading();
            window.location.href = $(e.currentTarget).attr('href');
          });
        }
        // If not processing, let the default link behavior happen
      },
      error: () => {
        // In case of error, just follow the link
      }
    });
  });

  // Handle file download with AJAX and blob response.
  $('.download-btn').on('click', function (e) {
    e.preventDefault();
    const uniqueFilename = $(this).data('filename');
    const originalFilename = $(this).data('download_name');
    
    // First check if verification is still in progress
    $.ajax({
      url: `/verification-status/${uniqueFilename}`,
      type: 'GET',
      success: (response) => {
        if (response.status === 'processing') {
          showLoading("Verification in progress... Please wait.");
          checkVerificationStatus(uniqueFilename, (success) => {
            downloadFile(uniqueFilename, originalFilename);
          });
        } else {
          downloadFile(uniqueFilename, originalFilename);
        }
      },
      error: () => {
        // In case of error checking status, try to download anyway
        downloadFile(uniqueFilename, originalFilename);
      }
    });
  });
  
  // Function to handle actual file download
  function downloadFile(uniqueFilename, originalFilename) {
    showLoading("Downloading file...");
    $.ajax({
      url: `/download/${uniqueFilename}`,
      type: 'GET',
      xhrFields: { responseType: 'blob' },
      success: (blob) => {
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
      error: (xhr) => {
        hideLoading();
        const errorMessage = xhr.responseJSON ? xhr.responseJSON.error : "File Not Found";
        displayMessage(errorMessage, true);
      }
    });
  }
});