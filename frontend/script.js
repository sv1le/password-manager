// ============================================
// CONFIGURATION
// ============================================
const API_URL = window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1'
    ? 'http://localhost:5000'
    : 'https://password-manager-g8vw.onrender.com';

let currentToken = null;
let currentUser = null;
let masterPassword = null;
let switchPollInterval = null;

// ============================================
// DOM ELEMENTS
// ============================================
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

const siteName = document.getElementById('site-name');
const siteUsername = document.getElementById('site-username');
const sitePassword = document.getElementById('site-password');
const addBtn = document.getElementById('add-btn');
const addError = document.getElementById('add-error');
const passwordsContainer = document.getElementById('passwords-container');

const sitePasswordInput = document.getElementById('site-password');
const strengthDiv = document.getElementById('password-strength');
const checkBreachBtn = document.getElementById('check-breach-btn');
const warningDiv = document.getElementById('breach-warning');

// ============================================
// CRYPTO — KEY DERIVATION / ENCRYPTION
// ============================================
function generateSalt() {
    const array = new Uint8Array(16);
    crypto.getRandomValues(array);
    return Array.from(array).map(b => b.toString(16).padStart(2, '0')).join('');
}

function generateIV() {
    const array = new Uint8Array(12);
    crypto.getRandomValues(array);
    return Array.from(array).map(b => b.toString(16).padStart(2, '0')).join('');
}

async function deriveKey(masterPassword, salt) {
    const encoder = new TextEncoder();
    const passwordBuffer = encoder.encode(masterPassword);
    const saltBuffer = encoder.encode(salt);
    const keyMaterial = await crypto.subtle.importKey('raw', passwordBuffer, 'PBKDF2', false, ['deriveKey']);

    return await crypto.subtle.deriveKey(
        { name: 'PBKDF2', salt: saltBuffer, iterations: 100000, hash: 'SHA-256' },
        keyMaterial,
        { name: 'AES-GCM', length: 256 },
        false,
        ['encrypt', 'decrypt']
    );
}

async function encryptData(data, key) {
    const encoder = new TextEncoder();
    const dataBuffer = encoder.encode(JSON.stringify(data));
    const iv = generateIV();
    const ivBuffer = new Uint8Array(iv.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));
    const encryptedBuffer = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: ivBuffer }, key, dataBuffer);
    const encryptedArray = new Uint8Array(encryptedBuffer);
    const encryptedHex = Array.from(encryptedArray).map(b => b.toString(16).padStart(2, '0')).join('');
    return { encrypted: encryptedHex, iv: iv };
}

async function decryptData(encryptedHex, iv, key) {
    const encryptedBytes = new Uint8Array(encryptedHex.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));
    const ivBytes = new Uint8Array(iv.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));
    const decryptedBuffer = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: ivBytes }, key, encryptedBytes);
    return JSON.parse(new TextDecoder().decode(decryptedBuffer));
}

async function hashPassword(password) {
    const encoder = new TextEncoder();
    const passwordBuffer = encoder.encode(password);
    const hashBuffer = await crypto.subtle.digest('SHA-256', passwordBuffer);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

// ============================================
// RSA KEY GENERATION (for sharing / switch)
// ============================================
async function generateRSAKeyPair(email) {
    if (localStorage.getItem(`pubKey_${email}`)) return;

    try {
        const keyPair = await crypto.subtle.generateKey(
            { name: "RSA-OAEP", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
            true,
            ["encrypt", "decrypt"]
        );

        const publicKey = await crypto.subtle.exportKey("spki", keyPair.publicKey);
        const privateKey = await crypto.subtle.exportKey("pkcs8", keyPair.privateKey);

        const pubBase64 = btoa(String.fromCharCode(...new Uint8Array(publicKey)));
        const privBase64 = btoa(String.fromCharCode(...new Uint8Array(privateKey)));

        localStorage.setItem(`pubKey_${email}`, pubBase64);
        localStorage.setItem(`privKey_${email}`, privBase64);

        console.log("✅ RSA Keys generated for sharing!");
    } catch (error) {
        console.error("❌ Failed to generate RSA keys:", error);
    }
}

function getPublicKey(email) {
    return localStorage.getItem(`pubKey_${email}`);
}

function getPrivateKey(email) {
    return localStorage.getItem(`privKey_${email}`);
}

// ============================================
// SHARING ENCRYPTION
// ============================================
async function createSecureShare(itemToShare, receiverPublicKeyBase64) {
    const aesKey = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"]);
    const encoder = new TextEncoder();
    const dataBuffer = encoder.encode(JSON.stringify(itemToShare));
    const iv = crypto.getRandomValues(new Uint8Array(12));

    const encryptedData = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, aesKey, dataBuffer);
    const rawAesKey = await crypto.subtle.exportKey("raw", aesKey);

    const cleanKey = receiverPublicKeyBase64.replace(/['"\s]+/g, '');
    const receiverPubKeyBuffer = Uint8Array.from(atob(cleanKey), c => c.charCodeAt(0));

    const receiverPubKey = await crypto.subtle.importKey(
        "spki",
        receiverPubKeyBuffer,
        { name: "RSA-OAEP", hash: "SHA-256" },
        false,
        ["encrypt"]
    );

    const encryptedAesKey = await crypto.subtle.encrypt({ name: "RSA-OAEP" }, receiverPubKey, rawAesKey);

    const shareBlob = {
        encryptedData: btoa(String.fromCharCode(...new Uint8Array(encryptedData))),
        encryptedKey: btoa(String.fromCharCode(...new Uint8Array(encryptedAesKey))),
        iv: btoa(String.fromCharCode(...new Uint8Array(iv)))
    };

    return JSON.stringify(shareBlob);
}

// ============================================
// SECURITY — HIBP BREACH CHECK
// ============================================
async function checkPwned(password) {
    if (!password) return null;
    const encoder = new TextEncoder();
    const data = encoder.encode(password);
    const hashBuffer = await crypto.subtle.digest('SHA-1', data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    const fullHash = hashArray.map(b => b.toString(16).padStart(2, '0')).join('').toUpperCase();

    try {
        const response = await fetch(`https://api.pwnedpasswords.com/range/${fullHash.substring(0, 5)}`);
        const text = await response.text();
        for (let line of text.split('\n')) {
            const [returnedSuffix, count] = line.split(':');
            if (returnedSuffix === fullHash.substring(5)) return parseInt(count);
        }
        return 0;
    } catch (error) {
        return null;
    }
}

// ============================================
// AUTH
// ============================================
async function register(email, password) {
    try {
        const passwordHash = await hashPassword(password);
        const response = await fetch(`${API_URL}/api/register`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email: email, password: passwordHash })
        });
        return await response.json();
    } catch (error) {
        return { status: 'error', message: error.message };
    }
}

async function login(email, password) {
    try {
        const passwordHash = await hashPassword(password);
        const response = await fetch(`${API_URL}/api/login`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email: email, password: passwordHash })
        });
        const data = await response.json();

        if (data.status === '2fa_required') {
            const code = prompt('🔐 Enter your 2FA code from Google Authenticator:');
            if (code) {
                const loginWith2FA = await fetch(`${API_URL}/api/login`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ email: email, password: passwordHash, totp_code: code })
                });
                return await loginWith2FA.json();
            }
            return { status: 'error', message: '2FA code required' };
        }
        return data;
    } catch (error) {
        return { status: 'error', message: error.message };
    }
}

// ============================================
// 2FA
// ============================================
async function check2FAStatus() {
    try {
        const response = await fetch(`${API_URL}/api/2fa/status`, {
            method: 'GET',
            headers: { 'Authorization': `Bearer ${currentToken}` }
        });
        return await response.json();
    } catch (error) {
        return { status: 'error', message: error.message };
    }
}

async function setup2FA() {
    try {
        const response = await fetch(`${API_URL}/api/2fa/setup`, {
            method: 'POST',
            headers: { 'Authorization': `Bearer ${currentToken}` }
        });
        return await response.json();
    } catch (error) {
        return { status: 'error', message: error.message };
    }
}

async function enable2FA(code) {
    try {
        const response = await fetch(`${API_URL}/api/2fa/enable`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${currentToken}` },
            body: JSON.stringify({ totp_code: code })
        });
        return await response.json();
    } catch (error) {
        return { status: 'error', message: error.message };
    }
}

async function load2FAStatus() {
    const statusText = document.getElementById('twofa-status-text');
    const setupBtn = document.getElementById('setup-2fa-btn');
    const disableBtn = document.getElementById('disable-2fa-btn');
    const setupDiv = document.getElementById('twofa-setup');
    if (!statusText) return;

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
        }
    } catch (error) {
        statusText.textContent = '❌ Error loading 2FA status';
    }
}

async function handleSetup2FA() {
    const setupBtn = document.getElementById('setup-2fa-btn');
    const setupDiv = document.getElementById('twofa-setup');
    const statusText = document.getElementById('twofa-status-text');
    const errorDiv = document.getElementById('twofa-error');

    setupBtn.textContent = '⏳ Generating...';
    setupBtn.disabled = true;
    errorDiv.textContent = '';

    const result = await setup2FA();
    setupBtn.textContent = 'Setup 2FA';
    setupBtn.disabled = false;

    if (result.status === 'success') {
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
        alert('✅ 2FA enabled successfully!');
        codeInput.value = '';
    } else {
        errorDiv.textContent = '❌ ' + (result.message || 'Invalid 2FA code.');
        setTimeout(() => errorDiv.textContent = '', 5000);
    }
}

async function handleDisable2FA() {
    if (!confirm('Are you sure you want to disable 2FA?')) return;
    try {
        const response = await fetch(`${API_URL}/api/2fa/disable`, {
            method: 'POST',
            headers: { 'Authorization': `Bearer ${currentToken}` }
        });
        const result = await response.json();
        if (result.status === 'success') {
            document.getElementById('twofa-status-text').textContent = '❌ 2FA is DISABLED';
            document.getElementById('twofa-status-text').style.color = '#ff4444';
            document.getElementById('setup-2fa-btn').style.display = 'inline-block';
            document.getElementById('disable-2fa-btn').style.display = 'none';
            alert('2FA has been disabled.');
        }
    } catch (error) {
        alert('Error disabling 2FA');
    }
}

// ============================================
// VAULT
// ============================================
async function saveVault(encryptedData, iv, salt) {
    try {
        const response = await fetch(`${API_URL}/api/vault`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${currentToken}` },
            body: JSON.stringify({ encrypted_data: encryptedData, iv: iv, salt: salt })
        });
        return await response.json();
    } catch (error) {
        return { status: 'error', message: error.message };
    }
}

async function getVault() {
    try {
        const response = await fetch(`${API_URL}/api/vault`, {
            method: 'GET',
            headers: { 'Authorization': `Bearer ${currentToken}` }
        });
        return await response.json();
    } catch (error) {
        return { status: 'error', message: error.message };
    }
}

function showAuth() {
    authSection.style.display = 'block';
    vaultSection.style.display = 'none';
    stopSwitchPolling();
}

function showVault() {
    authSection.style.display = 'none';
    vaultSection.style.display = 'block';
}

async function loadPasswords() {
    const result = await getVault();
    if (result.status === 'error' || !result.data) {
        passwordsContainer.innerHTML = '<div class="empty-state">🔐 No passwords saved yet.</div>';
        return;
    }

    try {
        const key = await deriveKey(masterPassword, result.data.salt);
        const decrypted = await decryptData(result.data.encrypted_data, result.data.iv, key);

        if (decrypted.length === 0) {
            passwordsContainer.innerHTML = '<div class="empty-state">🔐 No passwords saved yet.</div>';
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
                    <button class="share-btn" data-index="${index}" style="background: #00d4ff; color: #fff;">Share</button>
                    <button class="delete-btn" data-index="${index}">Delete</button>
                </div>
            `;
            passwordsContainer.appendChild(div);
        });

        document.querySelectorAll('.show-btn').forEach(btn => {
            btn.addEventListener('click', function () {
                const passwordEl = document.getElementById(`password-${this.dataset.index}`);
                if (passwordEl.textContent === '••••••••') {
                    passwordEl.textContent = decrypted[this.dataset.index].password;
                    this.textContent = 'Hide';
                } else {
                    passwordEl.textContent = '••••••••';
                    this.textContent = 'Show';
                }
            });
        });

        document.querySelectorAll('.delete-btn').forEach(btn => {
            btn.addEventListener('click', async function () {
                if (confirm(`Delete password for "${decrypted[this.dataset.index].site}"?`)) {
                    decrypted.splice(this.dataset.index, 1);
                    await saveAndReload(decrypted);
                }
            });
        });

        document.querySelectorAll('.share-btn').forEach(btn => {
            btn.addEventListener('click', async function () {
                const itemToShare = decrypted[this.dataset.index];
                const receiverEmail = prompt("Enter the receiver's email (they must have registered):");
                if (!receiverEmail) return;

                // We need their public key. Since it's device-bound, we ask the sender to paste it.
                const receiverPubKey = prompt(
                    `Paste ${receiverEmail}'s RSA Public Key.\n\n` +
                    `(They can find it in their browser localStorage under "pubKey_${receiverEmail.trim().toLowerCase()}" — or ask them to click "Copy My Public Key" next time they log in.)`
                );
                if (!receiverPubKey) return;

                try {
                    this.textContent = "Sharing...";
                    const sharedBlobString = await createSecureShare(itemToShare, receiverPubKey);

                    const response = await fetch(`${API_URL}/api/share`, {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${currentToken}` },
                        body: JSON.stringify({
                            shared_blob: sharedBlobString,
                            receiver_email: receiverEmail.trim().toLowerCase(),
                            hours_valid: 24
                        })
                    });

                    const data = await response.json();
                    if (data.status === 'success') {
                        alert(`✅ Share link created!\n\n${data.share_url}\n\nSend this link to ${receiverEmail}. It expires in 24 hours.`);
                    } else {
                        alert("❌ Failed to share: " + data.message);
                    }
                } catch (error) {
                    alert("❌ Error sharing password: " + error.message);
                }
                this.textContent = "Share";
            });
        });

    } catch (error) {
        console.error(error);
        passwordsContainer.innerHTML = '<div class="error">❌ Failed to decrypt vault.</div>';
    }
    await load2FAStatus();
    await loadSwitchStatus();
}

async function saveAndReload(passwords) {
    try {
        const salt = generateSalt();
        const key = await deriveKey(masterPassword, salt);
        const { encrypted, iv } = await encryptData(passwords, key);
        const result = await saveVault(encrypted, iv, salt);
        if (result.status === 'success') {
            await loadPasswords();
        }
    } catch (error) {
        addError.textContent = '❌ Failed to save password';
        setTimeout(() => addError.textContent = '', 3000);
    }
}

// ============================================
// PUBLIC KEY HELPER (so contacts can share their key)
// ============================================
function getMyPublicKey() {
    if (!currentUser) return null;
    return getPublicKey(currentUser.email);
}

async function handleCopyMyPublicKey() {
    const pubKey = getMyPublicKey();
    if (!pubKey) {
        alert("❌ No public key found. Try logging out and back in.");
        return;
    }
    try {
        await navigator.clipboard.writeText(pubKey);
        alert("✅ Your RSA Public Key has been copied to clipboard.\n\nShare it with anyone who wants to send you encrypted secrets (e.g., their Dead Man's Switch).");
    } catch (err) {
        // Fallback for browsers without clipboard API
        prompt("Copy your public key manually:", pubKey);
    }
}

// ============================================
// RECOVERY KIT
// ============================================
function generateRecoveryKey() {
    const array = new Uint8Array(16);
    crypto.getRandomValues(array);
    return Array.from(array).map(b => b.toString(16).padStart(2, '0')).join('').toUpperCase();
}

document.getElementById('recovery-btn').addEventListener('click', async () => {
    const recoveryKey = generateRecoveryKey();
    const salt = generateSalt();
    const recoveryCryptoKey = await deriveKey(recoveryKey, salt);

    const encoder = new TextEncoder();
    const dataBuffer = encoder.encode(masterPassword);
    const iv = generateIV();
    const ivBuffer = new Uint8Array(iv.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));

    const encryptedBuffer = await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv: ivBuffer },
        recoveryCryptoKey,
        dataBuffer
    );

    const encryptedArray = new Uint8Array(encryptedBuffer);
    const encryptedHex = Array.from(encryptedArray).map(b => b.toString(16).padStart(2, '0')).join('');
    const blob = JSON.stringify({ encrypted: encryptedHex, iv: iv, salt: salt });

    try {
        const response = await fetch(`${API_URL}/api/recovery/setup`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${currentToken}` },
            body: JSON.stringify({ encrypted_master_password: blob })
        });

        if (response.ok) {
            const printWindow = window.open('', '_blank');
            printWindow.document.write(`
                <html>
                <head>
                    <title>Emergency Recovery Kit</title>
                    <style>
                        body { font-family: monospace; padding: 40px; color: #000; }
                        .box { border: 2px dashed #000; padding: 20px; margin-top: 20px; text-align: center; }
                        h1 { text-align: center; }
                    </style>
                </head>
                <body>
                    <h1>🛡️ VaultGuard Emergency Recovery Kit</h1>
                    <p><strong>Account:</strong> ${currentUser.email}</p>
                    <p><strong>Date Generated:</strong> ${new Date().toLocaleDateString()}</p>
                    <hr>
                    <p><strong>YOUR RECOVERY CODE:</strong></p>
                    <div class="box">
                        <h2>${recoveryKey}</h2>
                    </div>
                    <p><strong>⚠️ WARNING:</strong> This is the ONLY way to recover your vault if you forget your Master Password. If someone else gets this code, they can access your vault. Print this and store it in a physical safe.</p>
                    <script>window.print();<\/script>
                </body>
                </html>
            `);
        } else {
            alert("Failed to save recovery kit to server.");
        }
    } catch (error) {
        alert("Failed to generate recovery kit.");
    }
});

// ============================================
// DEAD MAN'S SWITCH
// ============================================

/**
 * Load the current user's switch configuration and display status.
 * Also wires the "Activate" / "Disable" buttons dynamically.
 */
async function loadSwitchStatus() {
    const statusDiv = document.getElementById('switch-status');
    const setupBtn = document.getElementById('setup-switch-btn');
    if (!statusDiv) return;

    try {
        const response = await fetch(`${API_URL}/api/switch/status`, {
            method: 'GET',
            headers: { 'Authorization': `Bearer ${currentToken}` }
        });
        const data = await response.json();

        if (data.status !== 'success') {
            statusDiv.textContent = "❌ Could not load switch status.";
            statusDiv.style.color = "#ef4444";
            return;
        }

        const sw = data.switch;

        if (sw.state === 'inactive') {
            statusDiv.innerHTML = `💤 Not active.`;
            statusDiv.style.color = "#9ca3af";
            setupBtn.textContent = "Activate Switch";
        } else if (sw.state === 'active') {
            const days = sw.days_remaining ?? '?';
            statusDiv.innerHTML =
                `✅ <strong>Active</strong> — contact: <em>${sw.contact_email}</em><br>` +
                `⏳ ${days} day${days === 1 ? '' : 's'} until trigger`;
            statusDiv.style.color = "#10b981";
            setupBtn.textContent = "Update Switch";
        } else if (sw.state === 'triggered') {
            statusDiv.innerHTML = `🚨 <strong>TRIGGERED</strong> — contact ${sw.contact_email} has been notified.`;
            statusDiv.style.color = "#f59e0b";
            setupBtn.textContent = "Reset Switch";
        } else if (sw.state === 'claimed') {
            statusDiv.innerHTML = `🔓 <strong>Claimed</strong> by ${sw.contact_email}.`;
            statusDiv.style.color = "#00d4ff";
            setupBtn.textContent = "Reset Switch";
        }

        // Sync the email input from saved config
        const emailInput = document.getElementById('switch-email');
        if (emailInput && sw.contact_email) {
            emailInput.value = sw.contact_email;
        }
    } catch (err) {
        console.error("loadSwitchStatus error:", err);
        statusDiv.textContent = "❌ Network error loading switch status.";
        statusDiv.style.color = "#ef4444";
    }
}

/**
 * Arm (or update) the switch. Encrypts the master password with the CONTACT's RSA pubkey.
 */
document.getElementById('setup-switch-btn').addEventListener('click', async () => {
    const contactEmail = (document.getElementById('switch-email').value || '').trim().toLowerCase();
    const statusDiv = document.getElementById('switch-status');
    const btn = document.getElementById('setup-switch-btn');

    if (!contactEmail) {
        statusDiv.textContent = "⚠️ Please enter a valid email.";
        statusDiv.style.color = "#ef4444";
        return;
    }
    if (contactEmail === currentUser.email.toLowerCase()) {
        statusDiv.textContent = "⚠️ Contact email cannot be your own email.";
        statusDiv.style.color = "#ef4444";
        return;
    }

    const contactPubKey = prompt(
        `Paste ${contactEmail}'s RSA Public Key.\n\n` +
        `Ask them to click "📋 Copy My Public Key" on their dashboard and send it to you.`
    );
    if (!contactPubKey) return;

    try {
        btn.disabled = true;
        btn.textContent = "Encrypting...";
        statusDiv.textContent = "Encrypting your master password...";
        statusDiv.style.color = "#38bdf8";

        const cleanKey = contactPubKey.replace(/['"\s]+/g, '');
        const receiverPubKeyBuffer = Uint8Array.from(atob(cleanKey), c => c.charCodeAt(0));
        const receiverPubKey = await crypto.subtle.importKey(
            "spki", receiverPubKeyBuffer, { name: "RSA-OAEP", hash: "SHA-256" }, false, ["encrypt"]
        );

        const encoder = new TextEncoder();
        const encryptedMasterPwd = await crypto.subtle.encrypt(
            { name: "RSA-OAEP" },
            receiverPubKey,
            encoder.encode(masterPassword)
        );

        const blobBase64 = btoa(String.fromCharCode(...new Uint8Array(encryptedMasterPwd)));

        const response = await fetch(`${API_URL}/api/switch/setup`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${currentToken}` },
            body: JSON.stringify({ contact_email: contactEmail, encrypted_blob: blobBase64 })
        });

        const data = await response.json();
        if (data.status === 'success') {
            statusDiv.textContent = `✅ Switch armed for ${contactEmail}. You have ${data.timeout_days} days of inactivity before it triggers.`;
            statusDiv.style.color = "#10b981";
            await loadSwitchStatus();
        } else {
            throw new Error(data.message);
        }
    } catch (error) {
        statusDiv.textContent = "❌ Error: " + error.message;
        statusDiv.style.color = "#ef4444";
    } finally {
        btn.disabled = false;
        // Button text is refreshed by loadSwitchStatus
    }
});

/**
 * Check for any switches that have fired for THIS user (as contact).
 * Called on login and periodically. If triggered, asks user to claim.
 */
async function checkTriggeredSwitches() {
    try {
        const response = await fetch(`${API_URL}/api/switch/check`, {
            method: 'GET',
            headers: { 'Authorization': `Bearer ${currentToken}` }
        });
        const data = await response.json();

        if (data.status !== 'success' || !data.triggered_switches || data.triggered_switches.length === 0) {
            return;
        }

        for (const sw of data.triggered_switches) {
            const senderId = sw.sender_user_id;
            const senderEmail = sw.sender_email;

            const wantToClaim = confirm(
                `🚨 EMERGENCY ACCESS TRIGGERED\n\n` +
                `${senderEmail} has not logged in for ${data.timeout_days}+ days.\n\n` +
                `They designated YOU (${currentUser.email}) as their trusted contact.\n\n` +
                `Do you want to claim access and decrypt their vault now?`
            );

            if (wantToClaim) {
                await claimSwitch(senderId, senderEmail);
            }
        }
    } catch (error) {
        console.error("checkTriggeredSwitches error:", error);
    }
}

/**
 * Claim a triggered switch. Fetches the encrypted master-password blob AND the
 * sender's encrypted vault. Then decrypts both locally using THIS user's RSA
 * private key + recovered master password.
 */
async function claimSwitch(senderId, senderEmail) {
    try {
        // Step 1: This user's private key
        const privKeyBase64 = getPrivateKey(currentUser.email);
        if (!privKeyBase64) {
            alert(
                `❌ Private key not found on this device.\n\n` +
                `Your RSA private key is stored in this browser only. If you set up your account on a different device/browser, you cannot decrypt this switch here.`
            );
            return;
        }

        const privKeyBuffer = Uint8Array.from(atob(privKeyBase64), c => c.charCodeAt(0));
        const privKey = await crypto.subtle.importKey(
            "pkcs8", privKeyBuffer, { name: "RSA-OAEP", hash: "SHA-256" }, false, ["decrypt"]
        );

        // Step 2: Ask server for the claim payload (encrypted blob + encrypted vault)
        const response = await fetch(`${API_URL}/api/switch/claim/${senderId}`, {
            method: 'POST',
            headers: { 'Authorization': `Bearer ${currentToken}` }
        });
        const data = await response.json();

        if (data.status !== 'success') {
            alert("❌ Could not claim switch: " + data.message);
            return;
        }

        const payload = data.data;

        // Step 3: Decrypt the master password
        const encryptedBlobBytes = Uint8Array.from(atob(payload.encrypted_blob), c => c.charCodeAt(0));
        const decryptedMasterPwdBuffer = await crypto.subtle.decrypt(
            { name: "RSA-OAEP" }, privKey, encryptedBlobBytes
        );
        const recoveredMasterPassword = new TextDecoder().decode(decryptedMasterPwdBuffer);

        // Step 4: If we have the sender's vault, decrypt it and show the passwords
        let vaultPasswords = null;
        if (payload.vault) {
            try {
                const vaultKey = await deriveKey(recoveredMasterPassword, payload.vault.salt);
                vaultPasswords = await decryptData(
                    payload.vault.encrypted_data,
                    payload.vault.iv,
                    vaultKey
                );
            } catch (decErr) {
                console.error("Vault decrypt failed:", decErr);
                alert(
                    `🔓 Recovered Master Password for ${senderEmail}:\n\n${recoveredMasterPassword}\n\n` +
                    `⚠️ But the vault could not be decrypted (maybe the master password was changed after the switch was armed).`
                );
                return;
            }
        }

        // Step 5: Display results
        showClaimedVault(senderEmail, recoveredMasterPassword, vaultPasswords);

    } catch (error) {
        console.error("claimSwitch error:", error);
        alert("❌ Failed to claim switch: " + error.message);
    }
}

/**
 * Render claimed vault contents in a modal-ish overlay.
 */
/**
 * Render claimed vault contents in a modal-ish overlay.
 */
function showClaimedVault(senderEmail, recoveredMasterPassword, vaultPasswords) {
    const overlay = document.createElement('div');
    overlay.style.cssText =
        'position:fixed;inset:0;background:rgba(0,0,0,0.85);z-index:9999;' +
        'display:flex;align-items:center;justify-content:center;padding:20px;overflow:auto;';

    const box = document.createElement('div');
    box.style.cssText =
        'background:#0f172a;color:#e2e8f0;max-width:700px;width:100%;' +
        'padding:24px;border-radius:12px;border:1px solid #1e293b;' +
        'font-family:system-ui,sans-serif;max-height:90vh;overflow:auto;';

    let rows = '';
    if (vaultPasswords && vaultPasswords.length) {
        rows = vaultPasswords.map(p => `
            <div style="padding:10px;border-bottom:1px solid #1e293b;">
                <div style="font-weight:600;">🌐 ${escapeHtml(p.site)}</div>
                <div style="color:#94a3b8;">👤 ${escapeHtml(p.username)}</div>
                <div style="font-family:monospace;color:#00d4ff;">🔑 ${escapeHtml(p.password)}</div>
            </div>
        `).join('');
    } else {
        rows = '<div style="color:#94a3b8;padding:10px;">No vault entries could be decrypted.</div>';
    }

    box.innerHTML = `
        <h2 style="margin-top:0;color:#00d4ff;">🔓 Recovered Vault</h2>
        <p><strong>Owner:</strong> ${escapeHtml(senderEmail)}</p>
        <p><strong>Recovered Master Password:</strong></p>
        <div style="background:#020617;padding:12px;border-radius:8px;font-family:monospace;
                    color:#00d4ff;word-break:break-all;margin-bottom:16px;">
            ${escapeHtml(recoveredMasterPassword)}
        </div>
        <h3 style="color:#e2e8f0;">Vault Entries</h3>
        <div style="background:#020617;border-radius:8px;margin-bottom:16px;">
            ${rows}
        </div>
        <p style="color:#f59e0b;font-size:12px;">
            ⚠️ Store this information securely and delete it from your screen when done.
        </p>
        <button id="close-claimed-vault" style="background:#00d4ff;color:#020617;
                border:none;padding:10px 20px;border-radius:8px;cursor:pointer;
                font-weight:600;">Close</button>
    `;

    overlay.appendChild(box);
    document.body.appendChild(overlay);

    document.getElementById('close-claimed-vault').addEventListener('click', () => {
        overlay.remove();
    });
}

// Simple HTML escaper to prevent XSS in the modal
function escapeHtml(str) {
    if (str == null) return '';
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}

// ============================================
// SWITCH POLLING (periodically check for triggered switches)
// ============================================
function startSwitchPolling() {
    stopSwitchPolling();
    // Check every 60 seconds while the vault is open
    switchPollInterval = setInterval(() => {
        if (currentToken && vaultSection.style.display !== 'none') {
            checkTriggeredSwitches();
        }
    }, 60000);
}

function stopSwitchPolling() {
    if (switchPollInterval) {
        clearInterval(switchPollInterval);
        switchPollInterval = null;
    }
}

// ============================================
// PASSWORD STRENGTH + BREACH UI
// ============================================
function evaluateStrength(pw) {
    let score = 0;
    if (pw.length >= 8) score++;
    if (pw.length >= 12) score++;
    if (pw.length >= 16) score++;
    if (/[a-z]/.test(pw) && /[A-Z]/.test(pw)) score++;
    if (/\d/.test(pw)) score++;
    if (/[^A-Za-z0-9]/.test(pw)) score++;
    return score; // 0..6
}

if (sitePasswordInput && strengthDiv) {
    sitePasswordInput.addEventListener('input', () => {
        const pw = sitePasswordInput.value;
        const score = evaluateStrength(pw);
        if (!pw) {
            strengthDiv.textContent = '';
            return;
        }
        const labels = ['Very Weak', 'Weak', 'Fair', 'Okay', 'Good', 'Strong', 'Very Strong'];
        const colors = ['#ef4444', '#ef4444', '#f59e0b', '#f59e0b', '#10b981', '#10b981', '#00d4ff'];
        strengthDiv.textContent = `Strength: ${labels[score]}`;
        strengthDiv.style.color = colors[score];
    });
}

if (checkBreachBtn && warningDiv) {
    checkBreachBtn.addEventListener('click', async () => {
        const pw = sitePasswordInput ? sitePasswordInput.value : '';
        if (!pw) {
            warningDiv.textContent = '⚠️ Enter a password first.';
            warningDiv.style.color = '#f59e0b';
            return;
        }
        warningDiv.textContent = '🔍 Checking breach database...';
        warningDiv.style.color = '#94a3b8';

        const count = await checkPwned(pw);
        if (count === null) {
            warningDiv.textContent = '⚠️ Could not reach breach database.';
            warningDiv.style.color = '#f59e0b';
        } else if (count === 0) {
            warningDiv.textContent = '✅ This password was not found in known breaches.';
            warningDiv.style.color = '#10b981';
        } else {
            warningDiv.textContent = `🚨 This password has appeared in ${count.toLocaleString()} breaches! Do not use it.`;
            warningDiv.style.color = '#ef4444';
        }
    });
}

// ============================================
// AUTH UI HANDLERS
// ============================================
if (showRegister) {
    showRegister.addEventListener('click', (e) => {
        e.preventDefault();
        loginForm.style.display = 'none';
        registerForm.style.display = 'block';
        loginError.textContent = '';
        registerError.textContent = '';
    });
}

if (showLogin) {
    showLogin.addEventListener('click', (e) => {
        e.preventDefault();
        registerForm.style.display = 'none';
        loginForm.style.display = 'block';
        loginError.textContent = '';
        registerError.textContent = '';
    });
}

if (registerBtn) {
    registerBtn.addEventListener('click', async () => {
        const email = registerEmail.value.trim().toLowerCase();
        const password = registerPassword.value;
        registerError.textContent = '';

        if (!email || !password) {
            registerError.textContent = '⚠️ Email and password are required.';
            return;
        }
        if (password.length < 8) {
            registerError.textContent = '⚠️ Password must be at least 8 characters.';
            return;
        }

        registerBtn.disabled = true;
        registerBtn.textContent = '⏳ Creating...';

        const result = await register(email, password);

        registerBtn.disabled = false;
        registerBtn.textContent = 'Register';

        if (result.status === 'success') {
            // Generate RSA keys for this account on this device
            await generateRSAKeyPair(email);
            alert('✅ Account created! You can now log in.');
            registerForm.style.display = 'none';
            loginForm.style.display = 'block';
            loginEmail.value = email;
            loginPassword.value = '';
        } else {
            registerError.textContent = '❌ ' + (result.message || 'Registration failed.');
        }
    });
}

if (loginBtn) {
    loginBtn.addEventListener('click', async () => {
        const email = loginEmail.value.trim().toLowerCase();
        const password = loginPassword.value;
        loginError.textContent = '';

        if (!email || !password) {
            loginError.textContent = '⚠️ Email and password are required.';
            return;
        }

        loginBtn.disabled = true;
        loginBtn.textContent = '⏳ Logging in...';

        const result = await login(email, password);

        loginBtn.disabled = false;
        loginBtn.textContent = 'Login';

        if (result.status === 'success') {
            currentToken = result.token;
            currentUser = result.user;
            masterPassword = password; // used locally for vault decryption

            // Ensure RSA keys exist for sharing / switch on this device
            await generateRSAKeyPair(currentUser.email);

            showVault();
            await loadPasswords();

            // Check once immediately, then start polling
            await checkTriggeredSwitches();
            startSwitchPolling();
        } else {
            loginError.textContent = '❌ ' + (result.message || 'Login failed.');
        }
    });
}

if (logoutBtn) {
    logoutBtn.addEventListener('click', () => {
        currentToken = null;
        currentUser = null;
        masterPassword = null;
        passwordsContainer.innerHTML = '';
        loginPassword.value = '';
        showAuth();
    });
}

// ============================================
// ADD PASSWORD
// ============================================
if (addBtn) {
    addBtn.addEventListener('click', async () => {
        const site = siteName.value.trim();
        const username = siteUsername.value.trim();
        const password = sitePassword.value;
        addError.textContent = '';

        if (!site || !username || !password) {
            addError.textContent = '⚠️ All fields are required.';
            setTimeout(() => addError.textContent = '', 3000);
            return;
        }

        try {
            // Load existing vault entries first
            const vaultResult = await getVault();
            let entries = [];
            if (vaultResult.status === 'success' && vaultResult.data) {
                const key = await deriveKey(masterPassword, vaultResult.data.salt);
                entries = await decryptData(
                    vaultResult.data.encrypted_data,
                    vaultResult.data.iv,
                    key
                );
            }

            entries.push({ site, username, password });

            await saveAndReload(entries);

            siteName.value = '';
            siteUsername.value = '';
            sitePassword.value = '';
            if (strengthDiv) strengthDiv.textContent = '';
            if (warningDiv) warningDiv.textContent = '';
        } catch (error) {
            console.error(error);
            addError.textContent = '❌ Failed to save password.';
            setTimeout(() => addError.textContent = '', 3000);
        }
    });
}

// ============================================
// BOOT
// ============================================
(function init() {
    showAuth();
    // Wire the "copy my public key" button if present
    const copyBtn = document.getElementById('copy-pubkey-btn');
    if (copyBtn) {
        copyBtn.addEventListener('click', handleCopyMyPublicKey);
    }
    // Wire the disable-switch button if present
    const disableSwitchBtn = document.getElementById('disable-switch-btn');
    if (disableSwitchBtn) {
        disableSwitchBtn.addEventListener('click', async () => {
            if (!confirm('Disable your Dead Man\'s Switch?')) return;
            try {
                const res = await fetch(`${API_URL}/api/switch/disable`, {
                    method: 'POST',
                    headers: { 'Authorization': `Bearer ${currentToken}` }
                });
                const data = await res.json();
                if (data.status === 'success') {
                    await loadSwitchStatus();
                } else {
                    alert('❌ ' + (data.message || 'Failed to disable switch'));
                }
            } catch (err) {
                alert('❌ Network error disabling switch');
            }
        });
    }
})();