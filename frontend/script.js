// ============================================
// CONFIGURATION
// ============================================
const API_URL = 'http://localhost:5000';
let currentToken = null;
let currentUser = null;
let masterPassword = null; // Stored temporarily for encryption/decryption

// ============================================
// DOM ELEMENTS
// ============================================
// Auth elements
const authSection = document.getElementById('auth-section');
const vaultSection = document.getElementById('vault-section');
const loginForm = document.getElementById('login-form');
const registerForm = document.getElementById('register-form');
const loginEmail = document.getElementById('login-email');
const loginPassword = document.getElementById('login-password');
const registerEmail = document.getElementById('register-email');
const registerPassword = document.getElementById('register-password');
const loginBtn = document.getElementById('login-btn');
const registerBtn = document.getElementById('register-btn');
const loginError = document.getElementById('login-error');
const registerError = document.getElementById('register-error');
const showRegister = document.getElementById('show-register');
const showLogin = document.getElementById('show-login');
const logoutBtn = document.getElementById('logout-btn');

// Vault elements
const siteName = document.getElementById('site-name');
const siteUsername = document.getElementById('site-username');
const sitePassword = document.getElementById('site-password');
const addBtn = document.getElementById('add-btn');
const addError = document.getElementById('add-error');
const passwordsContainer = document.getElementById('passwords-container');

// ============================================
// CRYPTO FUNCTIONS (Web Crypto API)
// ============================================

// Generate random salt
function generateSalt() {
    const array = new Uint8Array(16);
    crypto.getRandomValues(array);
    return Array.from(array).map(b => b.toString(16).padStart(2, '0')).join('');
}

// Generate random IV
function generateIV() {
    const array = new Uint8Array(12);
    crypto.getRandomValues(array);
    return Array.from(array).map(b => b.toString(16).padStart(2, '0')).join('');
}

// Derive encryption key from master password using PBKDF2
async function deriveKey(masterPassword, salt) {
    const encoder = new TextEncoder();
    const passwordBuffer = encoder.encode(masterPassword);
    const saltBuffer = encoder.encode(salt);
    
    const keyMaterial = await crypto.subtle.importKey(
        'raw',
        passwordBuffer,
        'PBKDF2',
        false,
        ['deriveKey']
    );
    
    const key = await crypto.subtle.deriveKey(
        {
            name: 'PBKDF2',
            salt: saltBuffer,
            iterations: 100000,
            hash: 'SHA-256'
        },
        keyMaterial,
        {
            name: 'AES-GCM',
            length: 256
        },
        false,
        ['encrypt', 'decrypt']
    );
    
    return key;
}

// Encrypt data using AES-GCM
async function encryptData(data, key) {
    const encoder = new TextEncoder();
    const dataBuffer = encoder.encode(JSON.stringify(data));
    const iv = generateIV();
    const ivBuffer = new Uint8Array(iv.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));
    
    const encryptedBuffer = await crypto.subtle.encrypt(
        {
            name: 'AES-GCM',
            iv: ivBuffer
        },
        key,
        dataBuffer
    );
    
    const encryptedArray = new Uint8Array(encryptedBuffer);
    const encryptedHex = Array.from(encryptedArray)
        .map(b => b.toString(16).padStart(2, '0'))
        .join('');
    
    return { encrypted: encryptedHex, iv: iv };
}

// Decrypt data using AES-GCM
async function decryptData(encryptedHex, iv, key) {
    const encryptedBytes = new Uint8Array(encryptedHex.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));
    const ivBytes = new Uint8Array(iv.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));
    
    const decryptedBuffer = await crypto.subtle.decrypt(
        {
            name: 'AES-GCM',
            iv: ivBytes
        },
        key,
        encryptedBytes
    );
    
    const decoder = new TextDecoder();
    const decryptedText = decoder.decode(decryptedBuffer);
    return JSON.parse(decryptedText);
}
// ============================================
// 2FA FUNCTIONS
// ============================================

async function setup2FA() {
    try {
        const response = await fetch(`${API_URL}/api/2fa/setup`, {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${currentToken}`
            }
        });
        
        const data = await response.json();
        return data;
    } catch (error) {
        console.error('2FA setup error:', error);
        return { status: 'error', message: error.message };
    }
}

async function enable2FA(code) {
    try {
        const response = await fetch(`${API_URL}/api/2fa/enable`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${currentToken}`
            },
            body: JSON.stringify({ totp_code: code })
        });
        
        const data = await response.json();
        return data;
    } catch (error) {
        console.error('2FA enable error:', error);
        return { status: 'error', message: error.message };
    }
}

// ============================================
// 2FA UI Functions
// ============================================

async function load2FAStatus() {
    // Check if user has 2FA enabled (you'll need to add this to your login response)
    // For now, we'll check if we have a twofa_enabled flag
    // You can add this to the login response
}

async function handleSetup2FA() {
    const result = await setup2FA();
    
    if (result.status === 'success') {
        // Show QR code
        document.getElementById('qr-code-image').src = `data:image/png;base64,${result.qr_code}`;
        document.getElementById('twofa-secret').textContent = result.secret;
        document.getElementById('twofa-setup').style.display = 'block';
        document.getElementById('setup-2fa-btn').style.display = 'none';
        document.getElementById('twofa-status-text').textContent = 'Scan QR code with Google Authenticator';
    } else {
        document.getElementById('twofa-error').textContent = result.message;
    }
}

async function handleEnable2FA() {
    const code = document.getElementById('twofa-code-input').value;
    
    if (!code || code.length !== 6) {
        document.getElementById('twofa-error').textContent = 'Please enter a valid 6-digit code';
        return;
    }
    
    const result = await enable2FA(code);
    
    if (result.status === 'success') {
        document.getElementById('twofa-status-text').textContent = '✅ 2FA is ENABLED!';
        document.getElementById('twofa-setup').style.display = 'none';
        document.getElementById('disable-2fa-btn').style.display = 'inline-block';
        document.getElementById('twofa-error').textContent = '';
        alert('2FA enabled successfully! You\'ll need your authenticator app to login from now on.');
    } else {
        document.getElementById('twofa-error').textContent = result.message;
    }
}
// 2FA event listeners
document.getElementById('setup-2fa-btn').addEventListener('click', handleSetup2FA);
document.getElementById('enable-2fa-btn').addEventListener('click', handleEnable2FA);

// Hash password for authentication (simplified - in production use proper auth)
async function hashPassword(password) {
    const encoder = new TextEncoder();
    const passwordBuffer = encoder.encode(password);
    const hashBuffer = await crypto.subtle.digest('SHA-256', passwordBuffer);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

// ============================================
// AUTH FUNCTIONS
// ============================================

// Register user
async function register(email, password) {
    try {
        const passwordHash = await hashPassword(password);
        
        const response = await fetch(`${API_URL}/api/register`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                email: email,
                password: passwordHash
            })
        });
        
        const data = await response.json();
        return data;
    } catch (error) {
        console.error('Register error:', error);
        return { status: 'error', message: error.message };
    }
}
// Login user
async function login(email, password) {
    try {
        const passwordHash = await hashPassword(password);
        
        const response = await fetch(`${API_URL}/api/login`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                email: email,
                password: passwordHash
            })
        });
        
        const data = await response.json();
        
        // ============================================
        // CHECK IF 2FA IS REQUIRED
        // ============================================
        if (data.status === '2fa_required') {
            // Show 2FA popup or input
            const code = prompt('🔐 Enter your 2FA code from Google Authenticator:');
            
            if (code) {
                // Re-try login with 2FA code
                const loginWith2FA = await fetch(`${API_URL}/api/login`, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({
                        email: email,
                        password: passwordHash,
                        totp_code: code
                    })
                });
                
                const result2 = await loginWith2FA.json();
                
                // Return the 2FA login result
                if (result2.status === 'success') {
                    return result2;
                } else {
                    return { 
                        status: 'error', 
                        message: result2.message || 'Invalid 2FA code' 
                    };
                }
            } else {
                return { 
                    status: 'error', 
                    message: '2FA code is required to login' 
                };
            }
        }
        // ============================================
        // END 2FA CHECK
        // ============================================
        
        return data;
        
    } catch (error) {
        console.error('Login error:', error);
        return { status: 'error', message: error.message };
    }
}

// ============================================
// VAULT FUNCTIONS
// ============================================

// Save vault to server
async function saveVault(encryptedData, iv, salt) {
    try {
        const response = await fetch(`${API_URL}/api/vault`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${currentToken}`
            },
            body: JSON.stringify({
                encrypted_data: encryptedData,
                iv: iv,
                salt: salt
            })
        });
        
        const data = await response.json();
        return data;
    } catch (error) {
        console.error('Save vault error:', error);
        return { status: 'error', message: error.message };
    }
}

// Get vault from server
async function getVault() {
    try {
        const response = await fetch(`${API_URL}/api/vault`, {
            method: 'GET',
            headers: {
                'Authorization': `Bearer ${currentToken}`
            }
        });
        
        const data = await response.json();
        return data;
    } catch (error) {
        console.error('Get vault error:', error);
        return { status: 'error', message: error.message };
    }
}

// ============================================
// UI FUNCTIONS
// ============================================

// Show/hide auth/vault sections
function showAuth() {
    authSection.style.display = 'block';
    vaultSection.style.display = 'none';
}

function showVault() {
    authSection.style.display = 'none';
    vaultSection.style.display = 'block';
}

// Load passwords from vault
async function loadPasswords() {
    const result = await getVault();
    
    if (result.status === 'error') {
        passwordsContainer.innerHTML = `<div class="error">❌ ${result.message}</div>`;
        return;
    }
    
    if (!result.data) {
        passwordsContainer.innerHTML = '<div class="empty-state">🔐 No passwords saved yet. Add your first password above!</div>';
        return;
    }
    
    try {
        // Derive encryption key from master password
        const salt = result.data.salt;
        const key = await deriveKey(masterPassword, salt);
        
        // Decrypt the data
        const decrypted = await decryptData(result.data.encrypted_data, result.data.iv, key);
        
        // Display passwords
        if (decrypted.length === 0) {
            passwordsContainer.innerHTML = '<div class="empty-state">🔐 No passwords saved yet. Add your first password above!</div>';
            return;
        }
        
        passwordsContainer.innerHTML = '';
        decrypted.forEach((item, index) => {
            const div = document.createElement('div');
            div.className = 'password-item';
            div.innerHTML = `
                <div class="info">
                    <div class="site">🌐 ${item.site}</div>
                    <div class="username">👤 ${item.username}</div>
                    <div class="password" id="password-${index}">••••••••</div>
                </div>
                <div class="actions">
                    <button class="show-btn" data-index="${index}">Show</button>
                    <button class="delete-btn" data-index="${index}">Delete</button>
                </div>
            `;
            passwordsContainer.appendChild(div);
        });
        
        // Add event listeners for show/hide
        document.querySelectorAll('.show-btn').forEach(btn => {
            btn.addEventListener('click', function() {
                const index = parseInt(this.dataset.index);
                const passwordEl = document.getElementById(`password-${index}`);
                if (passwordEl.textContent === '••••••••') {
                    passwordEl.textContent = decrypted[index].password;
                    this.textContent = 'Hide';
                } else {
                    passwordEl.textContent = '••••••••';
                    this.textContent = 'Show';
                }
            });
        });
        
        // Add event listeners for delete
        document.querySelectorAll('.delete-btn').forEach(btn => {
            btn.addEventListener('click', async function() {
                const index = parseInt(this.dataset.index);
                if (confirm(`Delete password for "${decrypted[index].site}"?`)) {
                    decrypted.splice(index, 1);
                    await saveAndReload(decrypted);
                }
            });
        });
        
    } catch (error) {
        console.error('Decryption error:', error);
        passwordsContainer.innerHTML = '<div class="error">❌ Failed to decrypt vault. Wrong master password?</div>';
    }
    await load2FAStatus(); 
}

// Save and reload passwords
async function saveAndReload(passwords) {
    try {
        const salt = generateSalt();
        const key = await deriveKey(masterPassword, salt);
        const { encrypted, iv } = await encryptData(passwords, key);
        
        const result = await saveVault(encrypted, iv, salt);
        if (result.status === 'success') {
            await loadPasswords();
        } else {
            addError.textContent = '❌ Failed to save password';
            setTimeout(() => addError.textContent = '', 3000);
        }
    } catch (error) {
        console.error('Save error:', error);
        addError.textContent = '❌ Failed to save password';
        setTimeout(() => addError.textContent = '', 3000);
    }
}
// ============================================
// 2FA FUNCTIONS
// ============================================

// Check 2FA status for current user
async function check2FAStatus() {
    try {
        const response = await fetch(`${API_URL}/api/2fa/status`, {
            method: 'GET',
            headers: {
                'Authorization': `Bearer ${currentToken}`
            }
        });
        
        const data = await response.json();
        return data;
    } catch (error) {
        console.error('Check 2FA status error:', error);
        return { status: 'error', message: error.message };
    }
}

// Setup 2FA (get QR code and secret)
async function setup2FA() {
    try {
        const response = await fetch(`${API_URL}/api/2fa/setup`, {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${currentToken}`
            }
        });
        
        const data = await response.json();
        return data;
    } catch (error) {
        console.error('2FA setup error:', error);
        return { status: 'error', message: error.message };
    }
}

// Enable 2FA (verify code and enable)
async function enable2FA(code) {
    try {
        const response = await fetch(`${API_URL}/api/2fa/enable`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${currentToken}`
            },
            body: JSON.stringify({ totp_code: code })
        });
        
        const data = await response.json();
        return data;
    } catch (error) {
        console.error('2FA enable error:', error);
        return { status: 'error', message: error.message };
    }
}

// ============================================
// 2FA UI FUNCTIONS
// ============================================

// Load 2FA status when vault loads
async function load2FAStatus() {
    const statusText = document.getElementById('twofa-status-text');
    const setupBtn = document.getElementById('setup-2fa-btn');
    const disableBtn = document.getElementById('disable-2fa-btn');
    const setupDiv = document.getElementById('twofa-setup');
    
    try {
        const result = await check2FAStatus();
        
        if (result.status === 'success') {
            if (result.enabled) {
                statusText.textContent = '✅ 2FA is ENABLED';
                statusText.style.color = '#00d4ff';
                setupBtn.style.display = 'none';
                disableBtn.style.display = 'inline-block';
                setupDiv.style.display = 'none';
            } else {
                statusText.textContent = '❌ 2FA is DISABLED';
                statusText.style.color = '#ff4444';
                setupBtn.style.display = 'inline-block';
                disableBtn.style.display = 'none';
                setupDiv.style.display = 'none';
            }
        } else {
            statusText.textContent = ' Could not load 2FA status';
            statusText.style.color = '#ffaa00';
        }
    } catch (error) {
        console.error('Load 2FA status error:', error);
        statusText.textContent = ' Error loading 2FA status';
    }
}

// Handle Setup 2FA button click
async function handleSetup2FA() {
    const setupBtn = document.getElementById('setup-2fa-btn');
    const setupDiv = document.getElementById('twofa-setup');
    const statusText = document.getElementById('twofa-status-text');
    const errorDiv = document.getElementById('twofa-error');
    
    setupBtn.textContent = ' Generating...';
    setupBtn.disabled = true;
    errorDiv.textContent = '';
    
    const result = await setup2FA();
    
    setupBtn.textContent = 'Setup 2FA';
    setupBtn.disabled = false;
    
    if (result.status === 'success') {
        // Show QR code
        document.getElementById('qr-code-image').src = `data:image/png;base64,${result.qr_code}`;
        document.getElementById('twofa-secret').textContent = result.secret;
        setupDiv.style.display = 'block';
        setupBtn.style.display = 'none';
        statusText.textContent = '📱 Scan QR code with Google Authenticator';
        statusText.style.color = '#ffaa00';
    } else {
        errorDiv.textContent = '❌ ' + (result.message || 'Failed to setup 2FA');
        setTimeout(() => errorDiv.textContent = '', 5000);
    }
}

// Handle Enable 2FA button click
async function handleEnable2FA() {
    const codeInput = document.getElementById('twofa-code-input');
    const code = codeInput.value.trim();
    const errorDiv = document.getElementById('twofa-error');
    const enableBtn = document.getElementById('enable-2fa-btn');
    
    if (!code || code.length !== 6) {
        errorDiv.textContent = '⚠️ Please enter a valid 6-digit code';
        setTimeout(() => errorDiv.textContent = '', 3000);
        return;
    }
    
    enableBtn.textContent = '⏳ Verifying...';
    enableBtn.disabled = true;
    errorDiv.textContent = '';
    
    const result = await enable2FA(code);
    
    enableBtn.textContent = 'Enable 2FA';
    enableBtn.disabled = false;
    
    if (result.status === 'success') {
        document.getElementById('twofa-status-text').textContent = '✅ 2FA is ENABLED!';
        document.getElementById('twofa-status-text').style.color = '#00d4ff';
        document.getElementById('twofa-setup').style.display = 'none';
        document.getElementById('setup-2fa-btn').style.display = 'none';
        document.getElementById('disable-2fa-btn').style.display = 'inline-block';
        errorDiv.textContent = '';
        alert('✅ 2FA enabled successfully!\n\nYou\'ll need your authenticator app to login from now on.');
        codeInput.value = '';
    } else {
        errorDiv.textContent = '❌ ' + (result.message || 'Invalid 2FA code. Try again.');
        setTimeout(() => errorDiv.textContent = '', 5000);
    }
}

// Handle Disable 2FA button click
async function handleDisable2FA() {
    if (!confirm('Are you sure you want to disable 2FA?\n\nYour account will be less secure!')) {
        return;
    }
    
    try {
        const response = await fetch(`${API_URL}/api/2fa/disable`, {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${currentToken}`
            }
        });
        
        const result = await response.json();
        
        if (result.status === 'success') {
            document.getElementById('twofa-status-text').textContent = '❌ 2FA is DISABLED';
            document.getElementById('twofa-status-text').style.color = '#ff4444';
            document.getElementById('setup-2fa-btn').style.display = 'inline-block';
            document.getElementById('disable-2fa-btn').style.display = 'none';
            alert('2FA has been disabled.');
        } else {
            alert('Failed to disable 2FA: ' + result.message);
        }
    } catch (error) {
        console.error('Disable 2FA error:', error);
        alert('Error disabling 2FA');
    }
}

// ============================================
// EVENT LISTENERS
// ============================================
// 2FA Event Listeners
document.getElementById('setup-2fa-btn').addEventListener('click', handleSetup2FA);
document.getElementById('enable-2fa-btn').addEventListener('click', handleEnable2FA);
document.getElementById('disable-2fa-btn').addEventListener('click', handleDisable2FA);

// Enter key support for 2FA code input
document.getElementById('twofa-code-input').addEventListener('keypress', (e) => {
    if (e.key === 'Enter') {
        document.getElementById('enable-2fa-btn').click();
    }
});
// Show register form
showRegister.addEventListener('click', (e) => {
    e.preventDefault();
    loginForm.style.display = 'none';
    registerForm.style.display = 'block';
    loginError.textContent = '';
    registerError.textContent = '';
});

// Show login form
showLogin.addEventListener('click', (e) => {
    e.preventDefault();
    registerForm.style.display = 'none';
    loginForm.style.display = 'block';
    loginError.textContent = '';
    registerError.textContent = '';
});

// Register button
registerBtn.addEventListener('click', async () => {
    const email = registerEmail.value.trim();
    const password = registerPassword.value;
    
    if (!email || !password) {
        registerError.textContent = '⚠️ Please fill in all fields';
        setTimeout(() => registerError.textContent = '', 3000);
        return;
    }
    
    registerBtn.textContent = '⏳ Registering...';
    registerBtn.disabled = true;
    
    const result = await register(email, password);
    
    registerBtn.textContent = 'Register';
    registerBtn.disabled = false;
    
    if (result.status === 'success') {
        registerError.style.color = '#00d4ff';
        registerError.textContent = ' Registration successful! Please login.';
        setTimeout(() => {
            registerError.textContent = '';
            registerError.style.color = '#ff4444';
            registerForm.style.display = 'none';
            loginForm.style.display = 'block';
            registerEmail.value = '';
            registerPassword.value = '';
            loginEmail.value = email;
        }, 2000);
    } else {
        registerError.textContent = `❌ ${result.message || 'Registration failed'}`;
        setTimeout(() => registerError.textContent = '', 3000);
    }
});

// Login button
loginBtn.addEventListener('click', async () => {
    const email = loginEmail.value.trim();
    const password = loginPassword.value;
    
    if (!email || !password) {
        loginError.textContent = ' Please fill in all fields';
        setTimeout(() => loginError.textContent = '', 3000);
        return;
    }
    
    loginBtn.textContent = '⏳ Logging in...';
    loginBtn.disabled = true;
    
    const result = await login(email, password);
    
    loginBtn.textContent = 'Login';
    loginBtn.disabled = false;
    
    if (result.status === 'success') {
        currentToken = result.token;
        currentUser = result.user;
        masterPassword = password; // Store for encryption/decryption
        
        showVault();
        await loadPasswords();
    } else {
        loginError.textContent = `❌ ${result.message || 'Login failed'}`;
        setTimeout(() => loginError.textContent = '', 3000);
    }
});

// Add password button
addBtn.addEventListener('click', async () => {
    const site = siteName.value.trim();
    const username = siteUsername.value.trim();
    const password = sitePassword.value;
    
    if (!site || !username || !password) {
        addError.textContent = ' Please fill in all fields';
        setTimeout(() => addError.textContent = '', 3000);
        return;
    }
    
    addBtn.textContent = '⏳ Saving...';
    addBtn.disabled = true;
    
    try {
        // Get current passwords
        const result = await getVault();
        let passwords = [];
        
        if (result.data) {
            const key = await deriveKey(masterPassword, result.data.salt);
            passwords = await decryptData(result.data.encrypted_data, result.data.iv, key);
        }
        
        // Add new password
        passwords.push({ site, username, password });
        
        // Save updated vault
        const salt = generateSalt();
        const key = await deriveKey(masterPassword, salt);
        const { encrypted, iv } = await encryptData(passwords, key);
        
        const saveResult = await saveVault(encrypted, iv, salt);
        
        if (saveResult.status === 'success') {
            siteName.value = '';
            siteUsername.value = '';
            sitePassword.value = '';
            await loadPasswords();
        } else {
            addError.textContent = '❌ Failed to save password';
            setTimeout(() => addError.textContent = '', 3000);
        }
    } catch (error) {
        console.error('Add password error:', error);
        addError.textContent = '❌ Failed to save password';
        setTimeout(() => addError.textContent = '', 3000);
    }
    
    addBtn.textContent = 'Add Password';
    addBtn.disabled = false;
});

// Logout button
logoutBtn.addEventListener('click', () => {
    currentToken = null;
    currentUser = null;
    masterPassword = null;
    showAuth();
    loginPassword.value = '';
    loginEmail.value = '';
    passwordsContainer.innerHTML = '';
});

// Enter key support
loginPassword.addEventListener('keypress', (e) => {
    if (e.key === 'Enter') loginBtn.click();
});

registerPassword.addEventListener('keypress', (e) => {
    if (e.key === 'Enter') registerBtn.click();
});

sitePassword.addEventListener('keypress', (e) => {
    if (e.key === 'Enter') addBtn.click();
});

// ============================================
// INITIALIZATION
// ============================================
showAuth();
console.log(' Password Manager Frontend Loaded!');
console.log(' Backend API:', API_URL);
console.log(' Zero-Knowledge Architecture Active!');
console.log(' All encryption happens in your browser!');