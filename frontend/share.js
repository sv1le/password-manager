// ============================================
// CONFIGURATION
// ============================================
const API_URL = window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1'
    ? 'http://localhost:5000'
    : 'https://password-manager-g8vw.onrender.com';

// Get the Share ID from the URL (e.g., share.html?id=12345)
const urlParams = new URLSearchParams(window.location.search);
const shareId = urlParams.get('id');

const decryptBtn = document.getElementById('decrypt-btn');
const emailInput = document.getElementById('receiver-email');
const errorMsg = document.getElementById('error-msg');

// ============================================
// DECRYPTION LOGIC
// ============================================
async function decryptShare(shareBlobString, userEmail) {
    const shareBlob = JSON.parse(shareBlobString);
    
    // 1. Get the user's Private Key from localStorage
    const privBase64 = localStorage.getItem(`privKey_${userEmail}`);
    if (!privBase64) throw new Error("Private key not found for this email on this device. Are you on the correct browser?");

    // 2. Import the Private Key
    const privKeyBuffer = Uint8Array.from(atob(privBase64), c => c.charCodeAt(0));
    const privKey = await crypto.subtle.importKey(
        "pkcs8",
        privKeyBuffer,
        { name: "RSA-OAEP", hash: "SHA-256" },
        false,
        ["decrypt"]
    );

    // 3. Decrypt the AES Key
    const encryptedAesKey = Uint8Array.from(atob(shareBlob.encryptedKey), c => c.charCodeAt(0));
    const rawAesKey = await crypto.subtle.decrypt({ name: "RSA-OAEP" }, privKey, encryptedAesKey);

    // 4. Import the AES Key
    const aesKey = await crypto.subtle.importKey("raw", rawAesKey, { name: "AES-GCM" }, false, ["decrypt"]);

    // 5. Decrypt the Data
    const encryptedData = Uint8Array.from(atob(shareBlob.encryptedData), c => c.charCodeAt(0));
    const iv = Uint8Array.from(atob(shareBlob.iv), c => c.charCodeAt(0));

    const decryptedBuffer = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, aesKey, encryptedData);
    
    return JSON.parse(new TextDecoder().decode(decryptedBuffer));
}

// ============================================
// EVENT LISTENER
// ============================================
decryptBtn.addEventListener('click', async () => {
    const email = emailInput.value.trim();
    
    if (!shareId) {
        errorMsg.textContent = "❌ Invalid share link. No ID found.";
        return;
    }
    if (!email) {
        errorMsg.textContent = "⚠️ Please enter your email.";
        return;
    }

    decryptBtn.textContent = '⏳ Decrypting...';
    decryptBtn.disabled = true;
    errorMsg.textContent = '';

    try {
        // Fetch the encrypted blob from the backend
        const response = await fetch(`${API_URL}/api/share/${shareId}`);
        const data = await response.json();

        if (data.status === 'error') throw new Error(data.message);

        // Decrypt it locally
        const decryptedItem = await decryptShare(data.data.shared_blob, email);

        // Show the result on the screen
        document.getElementById('res-site').textContent = decryptedItem.site;
        document.getElementById('res-username').textContent = decryptedItem.username;
        document.getElementById('res-password').textContent = decryptedItem.password;
        
        document.getElementById('auth-step').style.display = 'none';
        document.getElementById('result-step').style.display = 'block';

    } catch (error) {
        console.error(error);
        errorMsg.textContent = "❌ Failed to decrypt. " + error.message;
    }

    decryptBtn.textContent = 'Decrypt Password';
    decryptBtn.disabled = false;
});