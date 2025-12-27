$(document).ready(() => {
    $('a[href="/list"]').on('click', function (event) {
      event.preventDefault();
      $('#loadingOverlay').show();
      $.ajax({
        url: '/list',
        type: 'GET',
        success: () => window.location.href = '/list',
        error: (xhr) => {
          $('#loadingOverlay').hide();
          const errorMessage = xhr.responseJSON ? xhr.responseJSON.error : "An error occurred";
          displayMessage(errorMessage, true);
        }
      });
    });
  });
  