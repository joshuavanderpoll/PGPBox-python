let keys

// Function to generate keys
function generateKeys() {
    const keyType = document.getElementById('keyType').value;
    const password = document.getElementById('keyPassword').value;
    const comment = document.getElementById('keyComment').value;
    const email = document.getElementById('keyEmail').value;

    fetch('/api/generate-keys', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({ keyType, password, comment, email })
    })
    .then(response => response.json())
    .then(data => {
        refreshKeyList()
        alert(data.message);
        document.getElementById('keyType').value = '';
        document.getElementById('keyPassword').value = '';
        document.getElementById('keyComment').value = '';
        document.getElementById('keyEmail').value = '';
    });
}

// Function to store keys
function storeKeys() {
    const key = document.getElementById('key').value;

    fetch('/api/store-keys', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({ key })
    })
    .then(response => response.json())
    .then(data => {
        refreshKeyList()
        alert(data.message);
        document.getElementById('key').value = '';
    });
}

// Function to view keys
function refreshKeyList() {
    fetch('/api/view-keys')
    .then(response => response.json())
    .then(data => {
        const keysList = document.getElementById('keysList');
        keysList.innerHTML = '';
        keys = data.keys;

        keys.forEach(key => {
            const copyPrivateKey = key.privateKey ? `<button class="copyPrivateKeyButton bg-red-500 text-white px-2 py-1 rounded" data-key="${key.privateKey}">Copy Private</button>` : '';

            const row = `<tr>
                <td class="border px-4 py-2">${formatFingerprint(key.fingerprint)}</td>
                <td class="border px-4 py-2">${key.email}</td>
                <td class="border px-4 py-2">${key.expirationDate}</td>
                <td class="border px-4 py-2">${key.notes}</td>
                <td class="border px-4 py-2">
                    <button class="copyPublicKeyButton bg-blue-500 text-white px-2 py-1 rounded" data-key="${key.publicKey}">Copy Public</button>
                    ${copyPrivateKey}
                    <button class="deleteKeyButton bg-red-500 text-white px-2 py-1 rounded" data-id="${key.id}">Delete</button>
                </td>
            </tr>`;
            keysList.innerHTML += row;
        });

        attachCopyEventListeners();
        refreshKeySelectors();
    });
}

// Function to refresh all key select dropdowns
function refreshKeySelectors() {
    const keySelects = document.querySelectorAll('.keySelector');

    keySelects.forEach(select => {
        const type = select.dataset.type;
        select.innerHTML = '<option selected disabled value="">-- select PGP key --</option>';

        keys.forEach(key => {
            const option = document.createElement('option');
            option.value = key.id;

            if(type === 'private' && key.privateKey === null) return;
            if(type === 'public' && key.publicKey === null) return;

            // Construct the display text
            const email = key.email || '';
            const comment = key.notes || '';
            const fingerprint = formatFingerprint(key.fingerprint);

            let displayText = '';
            if (email) displayText += email;
            if (email && comment) displayText += ' - ';
            if (comment) displayText += comment;

            if (email || comment) {
                displayText += ` (${fingerprint})`;
            } else {
                displayText += fingerprint;
            }

            option.text = displayText;
            select.appendChild(option);
        });
    });
}


// Function to confirm copying private key with a security notice
function confirmCopyPrivateKey(privateKey) {
    if (confirm("Are you sure you want to copy the private key? This is a sensitive action.")) {
        copyKey(privateKey, true);
    }
}

// Function to copy key to clipboard
function copyKey(key, isPrivate) {
    navigator.clipboard.writeText(key).then(() => {
        alert(`${isPrivate ? 'Private' : 'Public'} key copied to clipboard.`);
    });
}

// Function to delete a key
function deleteKey(id) {
    fetch('/api/delete-key', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({ id })
    })
    .then(response => response.json())
    .then(data => {
        refreshKeyList();
        alert(data.message);
    });
}

// Function to attach event listeners to copy buttons
function attachCopyEventListeners() {
    document.querySelectorAll('.copyPublicKeyButton').forEach(button => {
        button.addEventListener('click', function() {
            copyKey(this.dataset.key, false);
        });
    });

    document.querySelectorAll('.copyPrivateKeyButton').forEach(button => {
        button.addEventListener('click', function() {
            confirmCopyPrivateKey(this.dataset.key);
        });
    });

    document.querySelectorAll('.deleteKeyButton').forEach(button => {
        button.addEventListener('click', function() {
            if (confirm("Are you sure you want to delete this key?")) {
                deleteKey(this.dataset.id);
            }
        });
    });
}

// Function to encrypt a message
function encryptMessage() {
    const message = document.getElementById('messageToEncrypt').value;
    const key = document.getElementById('keySelectEncrypt').value;

    fetch('/api/encrypt-message', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({ message, key })
    })
    .then(response => response.json())
    .then(data => {
        const encryptedMessageField = document.getElementById('encryptedMessage');
        if(data.output) {
            encryptedMessageField.value = data.output;
        } else if(data.message) {
            alert(data.message);
        }
    });
}

// Function to decrypt a message
function decryptMessage() {
    const message = document.getElementById('messageToDecrypt').value;
    const privateKey = document.getElementById('privateKeySelect').value;
    const password = document.getElementById('privateKeyPassword').value;

    fetch('/api/decrypt-message', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({ message, privateKey, password })
    })
    .then(response => response.json())
    .then(data => {
        const encryptedMessageField = document.getElementById('decryptedMessage');
        if(data.output) {
            encryptedMessageField.value = data.output;
        } else if(data.message) {
            alert(data.message);
        }
    });
}

// Function to encrypt a message
function signMessage() {
    const message = document.getElementById('messageToSign').value;
    const privateKey = document.getElementById('signPrivateKeySelect').value;
    const password = document.getElementById('signPrivateKeyPassword').value;

    fetch('/api/sign-message', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({ message, privateKey, password })
    })
    .then(response => response.json())
    .then(data => {
        const signedMessageField = document.getElementById('signedMessage');
        if(data.output) {
            signedMessageField.value = data.output;
        } else if(data.message) {
            alert(data.message);
        }
    });
}

// Function to verify a signed message
function verifyMessage() {
    const message = document.getElementById('messageToVerify').value;
    const publicKey = document.getElementById('verifyPublicKeySelect').value;

    fetch('/api/verify-message', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({ message, publicKey })
    })
    .then(response => response.json())
    .then(data => {
        alert(data.message);
    });
}

// Function to select text in a textarea
function selectText(element) {
    element.select();
}

// Attach event listeners on document load
document.addEventListener('DOMContentLoaded', () => {
    refreshKeyList()
    
    document.getElementById('generateKeysButton').addEventListener('click', generateKeys);
    document.getElementById('storeKeysButton').addEventListener('click', storeKeys);
    document.getElementById('reloadKeysButton').addEventListener('click', refreshKeyList);
    document.getElementById('encryptMessageButton').addEventListener('click', encryptMessage);
    document.getElementById('decryptMessageButton').addEventListener('click', decryptMessage);
    document.getElementById('signMessageButton').addEventListener('click', signMessage);
    document.getElementById('verifyMessageButton').addEventListener('click', verifyMessage);
    
    document.querySelectorAll('textarea[readonly]').forEach(textarea => {
        textarea.addEventListener('click', function() {
            selectText(this);
        });
    });
});

function formatFingerprint(fingerprint) {
    return fingerprint.replace(/(.{4})/g, '$1 ');
}