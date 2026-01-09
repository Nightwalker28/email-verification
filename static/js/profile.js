function displayMessage(message, isError = false) {
    const messageContainer = $('#message-container');
    messageContainer.removeClass('d-none alert-success alert-danger');
    messageContainer.addClass(isError ? 'alert-danger' : 'alert-success');
    messageContainer.text(message);
    messageContainer.show();
    setTimeout(() => messageContainer.hide(), 5000);
  }
  
  $(document).ready(() => {
    $('form').on('submit', function(event) {
      event.preventDefault();
      const password = $('#password').val();
      const confirmPassword = $('#confirm_password').val();
      if (password || confirmPassword) {
        if (password !== confirmPassword) {
          alert('Passwords do not match. Please try again.');
          return;
        }
        // Optionally, add password strength validation here.
      }
      const formData = {
        first_name: $('#first_name').val(),
        last_name: $('#last_name').val(),
        password: password
      };
      $.ajax({
        url: '/profile',
        type: 'POST',
        contentType: 'application/json',
        data: JSON.stringify(formData),
        success: (response) => displayMessage(response.message, false),
        error: (xhr) => {
          const errorMessage = xhr.responseJSON ? xhr.responseJSON.error : "An error occurred";
          displayMessage(errorMessage, true);
        }
      });
    });
  });
  