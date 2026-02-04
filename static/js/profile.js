document.addEventListener("DOMContentLoaded", function() {
    
    const isGoogleLogin = JSON.parse(document.querySelector('script[data-google-login]')?.dataset.googleLogin || 'false');
    
    
    if (!isGoogleLogin) {
        const passwordFields = document.getElementById('passwordFields');
        if (passwordFields) {
            passwordFields.style.display = 'block';
        }
    } else {
        const googleLoginMessage = document.getElementById('googleLoginMessage');
        if (googleLoginMessage) {
            googleLoginMessage.style.display = 'block';
        }
    }
    
    
    const menuItems = document.querySelectorAll('.sidebar-menu a');
    const contentSections = document.querySelectorAll('.content-section');
    
    menuItems.forEach(item => {
        item.addEventListener('click', function(e) {
            e.preventDefault();
            
            
            menuItems.forEach(item => item.classList.remove('active'));
            
            
            this.classList.add('active');
            
            
            contentSections.forEach(section => section.classList.remove('active'));
            
            
            const targetId = this.getAttribute('href').substring(1);
            const targetSection = document.getElementById(targetId);
            if (targetSection) {
                targetSection.classList.add('active');
            }
        });
    });
    
    
    const passwordInput = document.getElementById('password');
    const confirmPasswordInput = document.getElementById('confirm_password');
    
    if (passwordInput) {
        passwordInput.addEventListener('input', validatePassword);
    }
    
    function validatePassword() {
        const password = passwordInput.value;
        const requirements = {
            length: password.length >= 8,
            uppercase: /[A-Z]/.test(password),
            lowercase: /[a-z]/.test(password),
            number: /\d/.test(password),
            special: /[@$!%*?&]/.test(password)
        };
        
        
        for (const [req, valid] of Object.entries(requirements)) {
            const element = document.getElementById(req);
            if (element) {
                if (valid) {
                    element.classList.add('valid');
                } else {
                    element.classList.remove('valid');
                }
            }
        }
    }
    
    
    function displayMessage(message, isError = false) {
        const messageContainer = document.getElementById('message-container');
        if (messageContainer) {
            messageContainer.classList.remove('alert-success', 'alert-danger', 'show');
            messageContainer.classList.add(isError ? 'alert-danger' : 'alert-success');
            messageContainer.textContent = message;
            messageContainer.classList.add('show');
            
            
            setTimeout(() => {
                messageContainer.classList.remove('show');
            }, 5000);
        }
    }
    
    
    const profileForm = document.getElementById('profileForm');
    if (profileForm) {
        profileForm.addEventListener('submit', function(e) {
            e.preventDefault();
            
            
            const formData = {
                first_name: document.getElementById('first_name').value,
                last_name: document.getElementById('last_name').value,
                company: document.getElementById('company').value
            };
            
            
            fetch('/profile', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify(formData)
            })
            .then(response => {
                if (!response.ok) {
                    return response.json().then(err => Promise.reject(err));
                }
                return response.json();
            })
            .then(data => {
                displayMessage(data.message || 'Profile updated successfully!', false);
            })
            .catch(error => {
                const errorMessage = error.error || "An error occurred";
                displayMessage(errorMessage, true);
            });
        });
    }
    
    
    const securityForm = document.getElementById('securityForm');
    if (securityForm) {
        securityForm.addEventListener('submit', function(e) {
            e.preventDefault();
            
            
            if (passwordInput && confirmPasswordInput) {
                if (passwordInput.value !== confirmPasswordInput.value) {
                    displayMessage('Passwords do not match. Please try again.', true);
                    return;
                }
                
                
                const passwordPattern = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/;
                if (passwordInput.value && !passwordPattern.test(passwordInput.value)) {
                    displayMessage('Password does not meet all requirements!', true);
                    return;
                }
            }
            
            
            const formData = {
                first_name: document.getElementById('first_name').value,
                last_name: document.getElementById('last_name').value
            };
            
            
            const currentPassword = document.getElementById('current_password');
            if (currentPassword && currentPassword.value) {
                formData.current_password = currentPassword.value;
            }
            
            if (passwordInput && passwordInput.value) {
                formData.password = passwordInput.value;
            }
            
            
            fetch('/profile', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify(formData)
            })
            .then(response => {
                if (!response.ok) {
                    return response.json().then(err => Promise.reject(err));
                }
                return response.json();
            })
            .then(data => {
                displayMessage(data.message || 'Password updated successfully!', false);
                
                if (currentPassword) currentPassword.value = '';
                if (passwordInput) passwordInput.value = '';
                if (confirmPasswordInput) confirmPasswordInput.value = '';
            })
            .catch(error => {
                const errorMessage = error.error || "An error occurred";
                displayMessage(errorMessage, true);
            });
        });
    }
    
    
    const twoFactorToggle = document.getElementById('twoFactorToggle');
    const twoFactorSetup = document.getElementById('twoFactorSetup');
    
    if (twoFactorToggle) {
        twoFactorToggle.addEventListener('change', function() {
            if (this.checked) {
                twoFactorSetup.style.display = 'block';
            } else {
                twoFactorSetup.style.display = 'none';
            }
        });
    }
    
    
    const showHideButtons = document.querySelectorAll('.show-hide-btn');
    showHideButtons.forEach(button => {
        button.addEventListener('click', function() {
            const input = this.parentElement.querySelector('input');
            if (input.type === 'password') {
                input.type = 'text';
                this.innerHTML = '<svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"></path><line x1="1" y1="1" x2="23" y2="23"></line></svg>';
            } else {
                input.type = 'password';
                this.innerHTML = '<svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path><circle cx="12" cy="12" r="3"></circle></svg>';
            }
        });
    });
    
    
    const copyButtons = document.querySelectorAll('.copy-btn');
    copyButtons.forEach(button => {
        button.addEventListener('click', function() {
            const input = this.parentElement.querySelector('input');
            const originalType = input.type;
            input.type = 'text';
            input.select();
            
            
            if (navigator.clipboard && window.isSecureContext) {
                navigator.clipboard.writeText(input.value).then(() => {
                    displayMessage('API key copied to clipboard!', false);
                }).catch(() => {
                    
                    document.execCommand('copy');
                    displayMessage('API key copied to clipboard!', false);
                });
            } else {
                
                document.execCommand('copy');
                displayMessage('API key copied to clipboard!', false);
            }
            
            input.type = originalType;
        });
    });
    
    
    const verificationInputs = document.querySelectorAll('.verification-input');
    verificationInputs.forEach((input, index) => {
        input.addEventListener('input', function() {
            if (this.value.length === 1) {
                if (index < verificationInputs.length - 1) {
                    verificationInputs[index + 1].focus();
                }
            }
        });
        
        input.addEventListener('keydown', function(e) {
            if (e.key === 'Backspace' && this.value.length === 0) {
                if (index > 0) {
                    verificationInputs[index - 1].focus();
                }
            }
        });
    });
});