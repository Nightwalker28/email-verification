// Utility to display messages; uses alert-success for normal and alert-danger for errors.
const displayMessage = (message, isError = false) => {
    const messageContainer = $('#message-container');
    messageContainer.removeClass('hidden alert-success alert-danger');
    messageContainer.addClass(isError ? 'alert-danger' : 'alert-success');
    messageContainer.text(message);
    messageContainer.show();
    setTimeout(() => messageContainer.hide(), 5000);
};

// Helper function to show loading state on button
const setButtonLoading = (button, isLoading, originalText) => {
    if (isLoading) {
        button.prop('disabled', true);
        button.html(`
            <svg class="spinner" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <circle cx="12" cy="12" r="10" stroke-opacity="0.25"/>
                <path d="M12 2a10 10 0 0 1 10 10" stroke-opacity="0.75">
                    <animateTransform attributeName="transform" type="rotate" dur="1s" repeatCount="indefinite" values="0 12 12;360 12 12"/>
                </path>
            </svg>
            Verifying...
        `);
    } else {
        button.prop('disabled', false);
        button.html(originalText);
    }
};

// Helper function to perform email verification via AJAX.
const performVerification = (url, emailAddress, buttonElement, originalButtonText) => {
    // Show loading state on the clicked button
    setButtonLoading(buttonElement, true, originalButtonText);
    
    $.ajax({
        url: url,
        type: 'POST',
        contentType: 'application/json',
        data: JSON.stringify({ email: emailAddress }),
        success: (response, status, xhr) => {
            // Reset button state
            setButtonLoading(buttonElement, false, originalButtonText);

            // Check if this is a silent HTML redirect (Flask sending the pricing page)
            if (
                typeof response === "string" &&
                response.includes('<title>Pricing') // or any unique element on the pricing page
            ) {
                window.location.href = '/pricing';
                return;
            }

            // Normal success path
            window.location.reload();
        },
        error: (xhr) => {
            // Reset button state
            setButtonLoading(buttonElement, false, originalButtonText);

            // Fallback: detect if redirect HTML landed in error handler
            if (xhr.status === 200 && xhr.responseText && xhr.responseText.includes('<title>Pricing')) {
                window.location.href = '/pricing';
                return;
            }

            const errorMessage = xhr.responseJSON?.error || "An error occurred";
            displayMessage(errorMessage, true);
        }
    });
};

$(document).ready(() => {
    // Store original button texts when the page loads
    const verifyButton = $('#manualEmailForm button[type="submit"]');
    const forceButton = $('#forceVerifyBtn');
    
    const originalVerifyText = verifyButton.length ? verifyButton.html() : 'Verify Email';
    const originalForceText = forceButton.length ? forceButton.html() : 'Force Verify';

    // Handle manual verification
    $('#manualEmailForm').on('submit', (event) => {
        event.preventDefault();
        const emailAddress = $('#emailAddress').val();
        performVerification('/verify', emailAddress, verifyButton, originalVerifyText);
    });

    // Handle forced verification (only if the button exists)
    if (forceButton.length) {
        forceButton.on('click', () => {
            const emailAddress = $('#emailAddress').val();
            performVerification('/force-verify', emailAddress, forceButton, originalForceText);
        });
    }
});