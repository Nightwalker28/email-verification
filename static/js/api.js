function displayMessage(message, isError = false) {
    const messageContainer = $('#message-container');
    messageContainer.removeClass('d-none alert-success alert-danger');
    messageContainer.addClass(isError ? 'alert-danger' : 'alert-success');
    messageContainer.text(message);
    messageContainer.show();
    setTimeout(() => messageContainer.hide(), 5000);  // Hide message after 5 seconds
}

$(document).ready(function() {

    // Show the modal when the button is clicked
    $('#createApiKeyBtn').click(() => {
        $('#createApiKeyModal').show();
    });
    $('#closeModalBtn').click(() => {
        $('#createApiKeyModal').hide();
    });

    // Prevent form submission after success
    $('#createApiKeyForm').submit(function(event) {
        event.preventDefault(); // Prevent the default form submission

        $.ajax({
            type: 'POST',
            url: '/create_api',
            data: $(this).serialize(),
            success: (response) => {
                if (response.success) {
                    $('#successMessage').text(response.success);  // Display the success message
                    $('#successModal').show();  // Show the success modal
                    $('#createApiKeyModal').hide();  // Close the Create API Key modal after success

                    // Extract the API key from the response.success string
                    const apiKey = response.success.split('Your API key is: ')[1];
                    $('#apiKeyText').text(apiKey);  // Set the API key text for copying
                }
            },
            error: (xhr) => {
                const errorMessage = xhr.responseJSON ? xhr.responseJSON.error : "An error occurred";
                displayMessage(errorMessage, true);
            }
        });
    });

    // Close success modal on button click
    $('#closeSuccessModalBtn').click(() => {
        $('#successModal').hide();
        window.location.reload();  // Reload page after closing modal
    });

    // Copy the API key to clipboard when the Copy button is clicked
    $('#copyApiKeyBtn').click(() => {
        const apiKey = $('#apiKeyText').text();  // Get the API key from the text
        navigator.clipboard.writeText(apiKey).then(() => {
            displayMessage('Key Copied Successfully');
        }).catch((err) => {
            console.error('Could not copy text: ', err);
            displayMessage('Failed to copy the API key');
        });
    });

    // Handle edit button click and show modal
    $('.editApiKeyBtn').click(function() {
        const row = $(this).closest('tr');
        const apiKeyId = row.data('id');
        const apiKeyName = row.find('td:first').text();

        $('#editApiKeyId').val(apiKeyId);
        $('#editName').val(apiKeyName);
        $('#editApiKeyModal').show();
    });

    // Close the edit modal
    $('#closeEditModalBtn').click(() => $('#editApiKeyModal').hide());

    // Handle form submission for editing API key
    $('#editApiKeyForm').submit(function(event) {
        event.preventDefault();

        $.ajax({
            type: 'POST',
            url: '/edit_api',
            data: $(this).serialize(),
            success: function(response) {
                // Access the 'success' key instead of 'message'
                location.reload();
            },
            error: function(xhr) {
                const errorMessage = xhr.responseJSON ? xhr.responseJSON.error : "An error occurred";
                displayMessage(errorMessage, true);
            }
        });
    });

    // Handle delete button click and remove the row on success
    $('.deleteApiKeyBtn').click(function() {
        const row = $(this).closest('tr');
        const apiKeyId = row.data('id');

        $.ajax({
            type: 'POST',
            url: '/delete_api',
            data: { id: apiKeyId },
            success: function(response) {
                row.remove()
                displayMessage(response.success, false);
            },
            error: function(xhr) {
                const errorMessage = xhr.responseJSON ? xhr.responseJSON.error : "An error occurred";
                displayMessage(errorMessage, true);
            }
        });
    });
});
