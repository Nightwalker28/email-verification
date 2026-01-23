// pricing.js - Fixed Modal functionality and form submission

// Modal functionality
function initializeModal() {
    const modal = document.getElementById('contact-modal');
    const contactBtn = document.getElementById('contact-us-btn');
    const closeBtn = document.querySelector('.close');
    const cancelBtn = document.getElementById('cancel-btn');
    const contactForm = document.getElementById('contact-form');
    const submitBtn = document.getElementById('submit-btn');

    if (!modal || !contactBtn) {
        console.error('Modal or contact button not found');
        return;
    }

    // Open modal
    contactBtn.addEventListener('click', function(e) {
        e.preventDefault();
        modal.style.display = 'flex'; 
        modal.classList.add('show');
        document.body.style.overflow = 'hidden'; 
        
        // Focus on first input for better UX
        setTimeout(() => {
            const firstInput = modal.querySelector('input[type="text"]');
            if (firstInput) firstInput.focus();
        }, 100);
    });

    // Close modal functions
    function closeModal() {
        modal.classList.remove('show');
        setTimeout(() => {
            modal.style.display = 'none';
        }, 300); 
        document.body.style.overflow = 'auto'; 
        if (contactForm) {
            contactForm.reset(); 
        }
        resetSubmitButton();
        
        // Clear any error messages
        const errorMessages = modal.querySelectorAll('.error-message');
        errorMessages.forEach(msg => msg.remove());
    }

    // Close modal events
    if (closeBtn) {
        closeBtn.addEventListener('click', closeModal);
    }

    if (cancelBtn) {
        cancelBtn.addEventListener('click', closeModal);
    }

    // Close modal when clicking outside
    window.addEventListener('click', function(event) {
        if (event.target === modal) {
            closeModal();
        }
    });

    // Close modal with Escape key
    document.addEventListener('keydown', function(event) {
        if (event.key === 'Escape' && modal.classList.contains('show')) {
            closeModal();
        }
    });

    // Handle form submission
    if (contactForm) {
        contactForm.addEventListener('submit', function(e) {
            e.preventDefault();
            
            // Clear previous error messages
            const errorMessages = modal.querySelectorAll('.error-message');
            errorMessages.forEach(msg => msg.remove());
            
            // Validate form before submission
            if (validateForm()) {
                handleFormSubmission();
            }
        });
    }

    // Add real-time validation
    const inputs = contactForm.querySelectorAll('input, textarea, select');
    inputs.forEach(input => {
        input.addEventListener('blur', function() {
            validateField(this);
        });
        
        input.addEventListener('input', function() {
            // Remove error styling when user starts typing
            this.classList.remove('error');
            const errorMsg = this.parentNode.querySelector('.field-error');
            if (errorMsg) errorMsg.remove();
        });
    });
}

// Validate individual field
function validateField(field) {
    const value = field.value.trim();
    let isValid = true;
    let message = '';

    // Remove previous error
    field.classList.remove('error');
    const existingError = field.parentNode.querySelector('.field-error');
    if (existingError) existingError.remove();

    // Check required fields
    if (field.hasAttribute('required') && !value) {
        isValid = false;
        message = 'This field is required';
    }
    
    // Email validation
    if (field.type === 'email' && value) {
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(value)) {
            isValid = false;
            message = 'Please enter a valid email address';
        }
    }

    // Show error if invalid
    if (!isValid) {
        field.classList.add('error');
        const errorDiv = document.createElement('div');
        errorDiv.className = 'field-error';
        errorDiv.textContent = message;
        field.parentNode.appendChild(errorDiv);
    }

    return isValid;
}

// Validate entire form
function validateForm() {
    const form = document.getElementById('contact-form');
    const requiredFields = form.querySelectorAll('[required]');
    let isValid = true;

    requiredFields.forEach(field => {
        if (!validateField(field)) {
            isValid = false;
        }
    });

    return isValid;
}

// Handle form submission with better error handling
function handleFormSubmission() {
    const submitBtn = document.getElementById('submit-btn');
    const btnText = submitBtn.querySelector('.btn-text');
    const spinner = submitBtn.querySelector('.spinner');
    const form = document.getElementById('contact-form');

    // Show loading state
    submitBtn.disabled = true;
    btnText.textContent = 'Sending...';
    spinner.style.display = 'inline-block';

    // Collect form data
    const formData = new FormData(form);
    
    // Create JSON payload
    const payload = {
        name: formData.get('name')?.trim() || '',
        email: formData.get('email')?.trim() || '',
        company: formData.get('company')?.trim() || 'Not provided',
        volume: formData.get('volume') || 'Not specified',
        message: formData.get('message')?.trim() || '',
        to_email: formData.get('to_email') || 'sheedh@acumenintelligence.com',
        subject: `Professional Plan Inquiry from ${formData.get('name')?.trim() || 'Unknown'}`
    };

    console.log('Sending payload:', payload);

    // Send form data to server
    fetch('/send-contact-email', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        },
        body: JSON.stringify(payload)
    })
    .then(response => {
        console.log('Response status:', response.status);
        console.log('Response headers:', response.headers);
        
        // Check if response is JSON
        const contentType = response.headers.get('content-type');
        if (contentType && contentType.includes('application/json')) {
            return response.json().then(data => {
                if (!response.ok) {
                    throw new Error(data.message || data.error || `Server error: ${response.status}`);
                }
                return data;
            });
        } else {
            // Handle non-JSON responses
            if (!response.ok) {
                throw new Error(`Server error: ${response.status} ${response.statusText}`);
            }
            return response.text().then(text => {
                // Try to parse as JSON, fallback to success message
                try {
                    return JSON.parse(text);
                } catch (e) {
                    return { success: true, message: 'Message sent successfully' };
                }
            });
        }
    })
    .then(result => {
        console.log('Success result:', result);
        if (result.success !== false) {
            showSubmissionSuccess();
        } else {
            showSubmissionError(result.message || result.error || 'Failed to send message');
        }
    })
    .catch(error => {
        console.error('Form Submission Error:', error);
        
        // Provide user-friendly error messages
        let errorMessage = 'An unexpected error occurred. Please try again.';
        
        if (error.message.includes('Failed to fetch')) {
            errorMessage = 'Network error. Please check your connection and try again.';
        } else if (error.message.includes('Server error: 404')) {
            errorMessage = 'The contact form endpoint was not found. Please contact support directly.';
        } else if (error.message.includes('Server error: 500')) {
            errorMessage = 'Server error occurred. Please try again later or contact support directly.';
        } else if (error.message) {
            errorMessage = error.message;
        }
        
        showSubmissionError(errorMessage);
    });
}

// Show success message with better styling
function showSubmissionSuccess() {
    const modalBody = document.querySelector('.modal-body');
    if (!modalBody) return;
    
    modalBody.innerHTML = `
        <div class="success-message">
            <div class="success-icon">
                <svg width="64" height="64" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"></path>
                    <polyline points="22,4 12,14.01 9,11.01"></polyline>
                </svg>
            </div>
            <h3>Message Sent Successfully!</h3>
            <p>
                Thank you for your interest in our Professional plan. Our team will review your requirements and get back to you within 24 hours.
            </p>
            <div class="success-actions">
                <button class="btn btn-primary" onclick="closeModalAndReload()">Close</button>
            </div>
        </div>
    `;
}

// Show error message with better styling
function showSubmissionError(message) {
    const modalBody = document.querySelector('.modal-body');
    if (!modalBody) return;
    
    // Remove existing error messages
    const existingErrors = modalBody.querySelectorAll('.error-message');
    existingErrors.forEach(error => error.remove());
    
    const errorDiv = document.createElement('div');
    errorDiv.className = 'error-message';
    errorDiv.innerHTML = `
        <div class="error-icon">
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <circle cx="12" cy="12" r="10"></circle>
                <line x1="15" y1="9" x2="9" y2="15"></line>
                <line x1="9" y1="9" x2="15" y2="15"></line>
            </svg>
        </div>
        <div class="error-content">
            <strong>Error:</strong> ${message}
        </div>
    `;
    
    // Insert error message at the top of the modal body
    modalBody.insertBefore(errorDiv, modalBody.firstChild);
    
    // Reset submit button
    resetSubmitButton();
    
    // Auto-remove error message after 8 seconds
    setTimeout(() => {
        if (errorDiv.parentNode) {
            errorDiv.remove();
        }
    }, 8000);
}

// Close modal and reload (for success state)
function closeModalAndReload() {
    const modal = document.getElementById('contact-modal');
    if (!modal) return;
    
    modal.classList.remove('show');
    setTimeout(() => {
        modal.style.display = 'none';
        document.body.style.overflow = 'auto';
        location.reload(); // Reload to reset the form
    }, 300);
}

// Reset submit button to normal state
function resetSubmitButton() {
    const submitBtn = document.getElementById('submit-btn');
    const btnText = submitBtn.querySelector('.btn-text');
    const spinner = submitBtn.querySelector('.spinner');
    
    if (submitBtn && btnText && spinner) {
        submitBtn.disabled = false;
        btnText.textContent = 'Send Message';
        spinner.style.display = 'none';
    }
}

// Initialize everything when DOM is loaded
document.addEventListener('DOMContentLoaded', function() {
    initializeModal();
});

// Make closeModalAndReload available globally for the success message
window.closeModalAndReload = closeModalAndReload;