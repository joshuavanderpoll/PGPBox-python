from flask import current_app as app, jsonify, request, render_template
from . import db
from .models import Key
import pgpy as PGPy
import re


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/api/generate-keys', methods=['POST'])
def generate_keys():
    data = request.json
    key_type = str(data.get('keyType'))
    password = str(data.get('password'))
    comment = str(data.get('comment'))
    email = str(data.get('email'))
    
    key_size = 4096
    if key_type == 'RSA-1024':
        key_size = 1024
    if key_type == 'RSA-2048':
        key_size = 2048

    # Generate PGP keys
    key = PGPy.PGPKey.new(PGPy.constants.PubKeyAlgorithm.RSAEncryptOrSign, key_size)
    uid = PGPy.PGPUID.new('', comment=comment, email=email)

    key.add_uid(uid, usage={PGPy.constants.KeyFlags.Sign, PGPy.constants.KeyFlags.EncryptCommunications},
        hashes=[PGPy.constants.HashAlgorithm.SHA256],
        ciphers=[PGPy.constants.SymmetricKeyAlgorithm.AES256],
        compression=[PGPy.constants.CompressionAlgorithm.ZLIB])
    
    # Protect the private key with a passphrase
    if password:
        key.protect(password, PGPy.constants.SymmetricKeyAlgorithm.AES256, PGPy.constants.HashAlgorithm.SHA256)

    public_key = str(key.pubkey)
    private_key = str(key)

    new_key = Key(public_key=public_key.strip(), private_key=private_key.strip())
    db.session.add(new_key)
    db.session.commit()

    return jsonify({
        'message': 'Keys generated successfully!',
        'public_key': public_key,
        'private_key': private_key
    })


@app.route('/api/store-keys', methods=['POST'])
def store_keys():
    data = request.json
    key_data = str(data.get('key'))

    # Initialize variables
    public_key_data = None
    private_key_data = None

    # Validate the provided key
    try:
        key = PGPy.PGPKey()
        key.parse(key_data)
        if key.is_public:
            public_key = key
            public_key_data = str(public_key)
        else:
            private_key = key
            private_key_data = str(private_key)
            public_key = private_key.pubkey
            public_key_data = str(public_key)
    except (PGPy.errors.PGPError, ValueError):
        return jsonify({'message': 'Invalid key'}), 400

    # Check if public key already exists
    existing_key = Key.query.filter_by(public_key=public_key_data.strip()).first()

    if existing_key:
        if private_key_data:
            # Update existing entry if public key already exists and private key is provided
            existing_key.private_key = private_key_data.strip()
            db.session.commit()
            return jsonify({'message': 'Public key updated with provided private key!'})
        else:
            return jsonify({'message': 'Public key already exists'}), 400

    # Check if private key already exists if provided
    if private_key_data and Key.query.filter_by(private_key=private_key_data.strip()).first():
        return jsonify({'message': 'Private key already exists'}), 400

    new_key = Key(
        public_key=public_key_data.strip(),
        private_key=private_key_data.strip() if private_key_data else None
    )

    db.session.add(new_key)
    db.session.commit()

    return jsonify({'message': 'Keys stored successfully!'})


@app.route('/api/view-keys', methods=['GET'])
def view_keys():
    keys = Key.query.all()
    keys_list = []

    for key in keys:
        key_info = {
            'publicKey': key.public_key,
            'privateKey': key.private_key
        }

        try:
            public_key = PGPy.PGPKey()
            public_key.parse(key.public_key)

            if public_key.is_public:
                uid = public_key.userids[0]
                key_info['id'] = key.id
                key_info['email'] = uid.email
                key_info['notes'] = uid.comment
                key_info['fingerprint'] = public_key.fingerprint
                key_info['expirationDate'] = str(public_key.expires_at) if public_key.expires_at else 'Never'
                keys_list.append(key_info)
        except (PGPy.errors.PGPError, ValueError):
            continue


    return jsonify({'keys': keys_list})


@app.route('/api/encrypt-message', methods=['POST'])
def encrypt_message():
    data = request.json

    message = str(data.get('message'))
    keyId = int(data.get('key'))
    
    key = Key.query.filter_by(id=keyId).first()
    if not key:
        return jsonify({'message': 'Public key not found'}), 404
    
    public_key = PGPy.PGPKey()
    public_key.parse(key.public_key)
    pgp_message = public_key.encrypt(PGPy.PGPMessage.new(message))

    return jsonify({'output': str(pgp_message)})


@app.route('/api/decrypt-message', methods=['POST'])
def decrypt_message():
    data = request.json

    message = str(data.get('message'))
    keyId = int(data.get('privateKey'))
    password = str(data.get('password'))

    key = Key.query.filter_by(id=keyId).first()
    if not key:
        return jsonify({'message': 'Private key not found'}), 404
    
    pgp_message = PGPy.PGPMessage()
    pgp_message.parse(message)
        
    # Decrypt the message
    private_key, _ = PGPy.PGPKey.from_blob(key.private_key)
    if private_key.is_protected and not private_key.is_unlocked:
        with private_key.unlock(password):
            decrypted_message = (private_key.decrypt(pgp_message)).message
    else:
        decrypted_message = (private_key.decrypt(pgp_message)).message

    return jsonify({'output': decrypted_message})


@app.route('/api/sign-message', methods=['POST'])
def sign_message():
    data = request.json

    message = str(data.get('message'))
    keyId = int(data.get('privateKey'))
    password = str(data.get('password'))

    key = Key.query.filter_by(id=keyId).first()
    if not key:
        return jsonify({'message': 'Private key not found'}), 404
        
    # Decrypt the message
    private_key, _ = PGPy.PGPKey.from_blob(key.private_key)

    if private_key.is_protected and not private_key.is_unlocked:
        try:
            with private_key.unlock(password):
                signature = str(private_key.sign(PGPy.PGPMessage.new(message), hash=PGPy.constants.HashAlgorithm.SHA512))
        except PGPy.errors.PGPDecryptionError:
            return jsonify({'message': 'Could not unlock private key. Is your password correct?'}), 400
    else:
        signature = str(private_key.sign(PGPy.PGPMessage.new(message), hash=PGPy.constants.HashAlgorithm.SHA512))

    signed_message = f"-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA512\n\n{message}\n{signature}"

    return jsonify({'output': signed_message})