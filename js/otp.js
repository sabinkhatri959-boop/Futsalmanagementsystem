// js/otp.js
// Client-side interactions for OTP verification page

document.addEventListener('DOMContentLoaded', function () {
    const otpForm = document.getElementById('otpForm');
    const otpInput = document.getElementById('otp');
    const otpAlert = document.getElementById('otp-alert');
    const verifyBtn = document.getElementById('verifyBtn');
    const resendBtn = document.getElementById('resendBtn');
    const timerSpan = document.getElementById('cooldown-timer');
    
    let cooldownTime = 60;
    let timerInterval = null;
    
    // Automatically start cooldown timer on page load
    startCooldown();
    
    // 1. Only allow digits in OTP input and auto-submit when 6 digits are entered
    if (otpInput) {
        otpInput.addEventListener('input', function() {
            // Keep only numbers
            this.value = this.value.replace(/\D/g, '');
            
            // Check for exact 6 digits to enable or disable verify button
            if (this.value.length === 6) {
                verifyBtn.removeAttribute('disabled');
            } else {
                verifyBtn.setAttribute('disabled', 'disabled');
            }
        });
        
        // Force numeric keyboard on mobile
        otpInput.setAttribute('inputmode', 'numeric');
    }
    
    // 2. OTP Form Submission (AJAX API call)
    if (otpForm) {
        otpForm.addEventListener('submit', function (e) {
            e.preventDefault();
            
            const otpCode = otpInput.value.trim();
            const csrfToken = otpForm.querySelector('input[name="csrf_token"]').value;
            
            if (otpCode.length !== 6) {
                showAlert('Verification code must be exactly 6 digits.', 'danger');
                return;
            }
            
            // Set loading visual state
            verifyBtn.setAttribute('disabled', 'disabled');
            verifyBtn.textContent = 'VERIFYING...';
            hideAlert();
            
            const formData = new FormData();
            formData.append('otp', otpCode);
            formData.append('csrf_token', csrfToken);
            
            fetch('api/verify_otp.php', {
                method: 'POST',
                body: formData
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    // Redirect to corresponding dashboard
                    window.location.href = data.redirect;
                } else {
                    showAlert(data.error, 'danger');
                    otpInput.value = '';
                    verifyBtn.setAttribute('disabled', 'disabled');
                    verifyBtn.textContent = 'VERIFY CODE';
                    otpInput.focus();
                }
            })
            .catch(error => {
                console.error('Error:', error);
                showAlert('A network error occurred. Please try again.', 'danger');
                verifyBtn.removeAttribute('disabled');
                verifyBtn.textContent = 'VERIFY CODE';
            });
        });
    }
    
    // 3. Resend OTP Button Handler
    if (resendBtn) {
        resendBtn.addEventListener('click', function () {
            const csrfToken = otpForm.querySelector('input[name="csrf_token"]').value;
            
            // Disable button immediately
            resendBtn.setAttribute('disabled', 'disabled');
            hideAlert();
            
            const formData = new FormData();
            formData.append('csrf_token', csrfToken);
            
            fetch('api/resend_otp.php', {
                method: 'POST',
                body: formData
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    showAlert(data.message, 'success');
                    // Reset and start cooldown
                    cooldownTime = 60;
                    startCooldown();
                } else {
                    showAlert(data.error, 'danger');
                    // Enable button if it was a rate limit or failure
                    if (data.seconds_left) {
                        cooldownTime = parseInt(data.seconds_left);
                        startCooldown();
                    } else {
                        resendBtn.removeAttribute('disabled');
                    }
                }
            })
            .catch(error => {
                console.error('Error:', error);
                showAlert('A network error occurred while resending the code.', 'danger');
                resendBtn.removeAttribute('disabled');
            });
        });
    }
    
    // Helper to start the resend button cooldown countdown
    function startCooldown() {
        if (timerInterval) {
            clearInterval(timerInterval);
        }
        
        resendBtn.setAttribute('disabled', 'disabled');
        timerSpan.style.display = 'inline';
        timerSpan.textContent = `(${cooldownTime}s)`;
        
        timerInterval = setInterval(() => {
            cooldownTime--;
            if (cooldownTime <= 0) {
                clearInterval(timerInterval);
                resendBtn.removeAttribute('disabled');
                timerSpan.style.display = 'none';
            } else {
                timerSpan.textContent = `(${cooldownTime}s)`;
            }
        }, 1000);
    }
    
    // Helper to display error or success messages
    function showAlert(message, type) {
        if (!otpAlert) return;
        
        otpAlert.textContent = message;
        otpAlert.style.display = 'block';
        
        if (type === 'success') {
            otpAlert.style.backgroundColor = 'rgba(16, 185, 129, 0.12)';
            otpAlert.style.color = '#6ee7b7';
            otpAlert.style.borderColor = 'rgba(16, 185, 129, 0.3)';
        } else {
            // Default danger layout matching style.css
            otpAlert.style.backgroundColor = 'rgba(239, 68, 68, 0.1)';
            otpAlert.style.color = '#f87171';
            otpAlert.style.borderColor = 'rgba(239, 68, 68, 0.3)';
        }
    }
    
    function hideAlert() {
        if (otpAlert) {
            otpAlert.style.display = 'none';
            otpAlert.textContent = '';
        }
    }
});
