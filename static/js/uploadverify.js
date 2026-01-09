// Utility to display messages; uses alert-success for normal and alert-danger for errors.
const displayMessage = (message, isError = false) => {
    const messageContainer = $('#message-container');
    messageContainer.removeClass('d-none alert-success alert-danger');
    messageContainer.addClass(isError ? 'alert-danger' : 'alert-success');
    messageContainer.text(message);
    messageContainer.show();
    setTimeout(() => messageContainer.hide(), 5000);
  };
  
  $(document).ready(() => {
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
    $('#uploadForm').on('submit', function (event) {
      event.preventDefault();
      const formData = new FormData(this);
      $.ajax({
        url: '/upload',
        type: 'POST',
        data: formData,
        contentType: false,
        processData: false,
        success: () => window.location.reload(),
        error: (xhr) => {
          const errorMessage = xhr.responseJSON ? xhr.responseJSON.error : "An error occurred";
          displayMessage(errorMessage, true);
        }
      });
    });
  
    // Handle force file upload.
    $('#forceVerifyBtn').on('click', () => {
      const formData = new FormData($('#uploadForm')[0]);
      $.ajax({
        url: '/force-upload',
        type: 'POST',
        data: formData,
        contentType: false,
        processData: false,
        success: () => window.location.reload(),
        error: (xhr) => {
          const errorMessage = xhr.responseJSON ? xhr.responseJSON.error : "An error occurred";
          displayMessage(errorMessage, true);
        }
      });
    });
  
    // Handle file download with AJAX and blob response.
    $('.download-btn').on('click', function (e) {
      e.preventDefault();
      const uniqueFilename = $(this).data('filename');
      const originalFilename = $(this).data('download_name');
      $.ajax({
        url: `/download/${uniqueFilename}`,
        type: 'GET',
        xhrFields: { responseType: 'blob' },
        success: (blob) => {
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
          const errorMessage = xhr.responseJSON ? xhr.responseJSON.error : "File Not Found";
          displayMessage(errorMessage, true);
        }
      });
    });
  });
  