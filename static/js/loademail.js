document.getElementById("passwrdForm").addEventListener("submit", function(event) {
    event.preventDefault();  // Prevent form submission
    const emailAddress = document.getElementById("emailAddress").value;

    // Send the email to the backend
    fetch('/request_password_reset', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({ emailAddress: emailAddress })
    })
    .then(response => {
        if (!response.ok) {
            throw new Error(`HTTP error! Status: ${response.status}`);
        }
        return response.json();  // Parse JSON response
    })
    .then(data => {
        // Display the returned JSON data in the UI
        const resultDiv = document.getElementById("result"); // Div to show the result

        // Check for the type of response sent back from the server
        if (data.error) {
            resultDiv.innerHTML = data.error;  // Show error message if present
        } else {
            resultDiv.innerHTML = data.message; // Show success message
        }
    })
    .catch(error => {
        console.error("Error:", error);
        const resultDiv = document.getElementById("result");
        resultDiv.innerHTML = "An error occurred. Please try again.";
    });
});
