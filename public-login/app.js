document.addEventListener('DOMContentLoaded', () => {
    const authForm = document.getElementById('authForm');
    const btn = document.getElementById('submitBtn');
    const alertBox = document.getElementById('alertBox');
    const apiUrlInput = document.getElementById('apiUrl');
    
    const formTitle = document.getElementById('formTitle');
    const formSubtitle = document.getElementById('formSubtitle');
    const deptGroup = document.getElementById('deptGroup');
    const passGroup = document.getElementById('passGroup');
    const passwordInput = document.getElementById('password');
    const toggleMode = document.getElementById('toggleMode');
    const toggleText = document.getElementById('toggleText');

    let isLoginMode = true;

    toggleMode.addEventListener('click', (e) => {
        e.preventDefault();
        isLoginMode = !isLoginMode;
        
        if (isLoginMode) {
            formTitle.textContent = 'Enterprise Portal';
            formSubtitle.textContent = 'Sign in to access your workspace';
            deptGroup.style.display = 'none';
            passGroup.style.display = 'block';
            passwordInput.required = true;
            btn.textContent = 'Sign In';
            toggleText.innerHTML = 'Don\'t have an account? <a href="#" id="toggleMode" style="color: var(--primary); text-decoration: none;">Register here</a>';
        } else {
            formTitle.textContent = 'Access Request';
            formSubtitle.textContent = 'Request access to the enterprise portal';
            deptGroup.style.display = 'block';
            passGroup.style.display = 'none';
            passwordInput.required = false;
            btn.textContent = 'Request Access';
            toggleText.innerHTML = 'Already have an account? <a href="#" id="toggleMode" style="color: var(--primary); text-decoration: none;">Sign in here</a>';
        }

        
        // Re-attach event listener to the new toggleMode element if innerHTML was used
        document.getElementById('toggleMode').addEventListener('click', (e) => {
            e.preventDefault();
            toggleMode.click();
        });
    });

    function showAlert(message, type) {
        alertBox.textContent = message;
        alertBox.className = `alert alert-${type}`;
    }

    function hideAlert() {
        alertBox.className = 'alert';
    }

    authForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        hideAlert();
        
        const username = document.getElementById('username').value.trim();
        const password = document.getElementById('password').value;
        const department = document.getElementById('department').value.trim();
        const baseUrl = apiUrlInput.value.replace(/\/$/, "") || window.location.origin; 

        if (!username || (isLoginMode && !password) || (!isLoginMode && !department)) {
            showAlert('Please fill in all required fields', 'error');
            return;
        }

        btn.disabled = true;
        btn.textContent = isLoginMode ? 'Verifying...' : 'Submitting Request...';

        try {
            const endpoint = isLoginMode ? '/api/auth/login' : '/api/auth/register';
            const body = isLoginMode 
                ? { username, password } 
                : { username, department };


            const response = await fetch(`${baseUrl}${endpoint}`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(body)
            });

            const data = await response.json();

            if (response.ok && data.success) {
                showAlert(data.message, 'success');
                
                if (isLoginMode) {
                    btn.textContent = 'Authenticated';
                } else {
                    btn.textContent = 'Submitted';
                    setTimeout(() => {
                        isLoginMode = false;
                        toggleMode.click(); // Switch back to login mode
                    }, 2000);
                }
                
                setTimeout(() => {
                    authForm.reset();
                    btn.disabled = false;
                    btn.textContent = isLoginMode ? 'Sign In' : 'Register';
                }, 3000);
            } else {
                showAlert(data.detail || data.message || 'Action failed', 'error');
                btn.disabled = false;
                btn.textContent = isLoginMode ? 'Sign In' : 'Register';
            }
        } catch (error) {
            console.error(error);
            showAlert('Connection error. Is the Backend running and Ngrok URL correct?', 'error');
            btn.disabled = false;
            btn.textContent = isLoginMode ? 'Sign In' : 'Register';
        }
    });
});

