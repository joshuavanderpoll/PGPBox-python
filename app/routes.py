from flask import current_app as app, jsonify, request, render_template
from . import db
from .models import Key
import pgpy as PGPy


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
    uid = PGPy.PGPUID.new(comment, comment=comment, email=email)

    key.add_uid(uid, usage={PGPy.constants.KeyFlags.Sign, PGPy.constants.KeyFlags.EncryptCommunications},
        hashes=[PGPy.constants.HashAlgorithm.SHA512],
        ciphers=[PGPy.constants.SymmetricKeyAlgorithm.AES256],
        compression=[PGPy.constants.CompressionAlgorithm.ZLIB])
    
    # Protect the private key with a passphrase
    if password:
        key.protect(password, PGPy.constants.SymmetricKeyAlgorithm.AES256, PGPy.constants.HashAlgorithm.SHA512)

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
                try:
                    uid = public_key.userids[0]
                    key_info['id'] = key.id
                    key_info['email'] = uid.email
                    key_info['notes'] = uid.comment
                    key_info['fingerprint'] = public_key.fingerprint
                    key_info['expirationDate'] = str(public_key.expires_at) if public_key.expires_at else 'Never'
                    keys_list.append(key_info)
                except IndexError:
                    continue
        except (PGPy.errors.PGPError, ValueError):
            continue


    return jsonify({'keys': keys_list})


@app.route('/api/encrypt-message', methods=['POST'])
def encrypt_message():
    data = request.json

    if not data.get('message') or not data.get('key'):
        return jsonify({'message': 'Missing required fields'}), 400

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

    if not data.get('message') or not data.get('privateKey'):
        return jsonify({'message': 'Missing required fields'}), 400

    message = str(data.get('message'))
    keyId = int(data.get('privateKey'))
    password = str(data.get('password')) if data.get('password') else None

    key = Key.query.filter_by(id=keyId).first()
    if not key:
        return jsonify({'message': 'Private key not found'}), 404
    
    pgp_message = PGPy.PGPMessage.from_blob(message)
        
    # Decrypt the message
    private_key, _ = PGPy.PGPKey.from_blob(key.private_key)
    if private_key.is_protected and not private_key.is_unlocked:
        if not password:
            return jsonify({'message': 'Private key is protected. Password is required'}), 400
        
        try:
            with private_key.unlock(password):
                try:
                    decrypted_message = (private_key.decrypt(pgp_message)).message
                except Exception:
                    return jsonify({'message': 'Could not decrypt message'}), 400
        except PGPy.errors.PGPDecryptionError:
            return jsonify({'message': 'Could not unlock private key. Is your password correct?'}), 400
    else:
        decrypted_message = (private_key.decrypt(pgp_message)).message

    if isinstance(decrypted_message, bytearray):
        decrypted_message = decrypted_message.decode('utf-8')

    return jsonify({'output': decrypted_message})


@app.route('/api/sign-message', methods=['POST'])
def sign_message():
    data = request.json

    if not data.get('message') or not data.get('privateKey'):
        return jsonify({'message': 'Missing required fields'}), 400

    message = str(data.get('message'))
    keyId = int(data.get('privateKey'))
    password = str(data.get('password')) if data.get('password') else None

    key = Key.query.filter_by(id=keyId).first()
    if not key:
        return jsonify({'message': 'Private key not found'}), 404

    pgp_message = PGPy.PGPMessage.new(message, cleartext=True)
        
    # Sign the message
    private_key, _ = PGPy.PGPKey.from_blob(key.private_key)
    if private_key.is_protected and not private_key.is_unlocked:
        if not password:
            return jsonify({'message': 'Private key is protected. Password is required'}), 400

        try:
            with private_key.unlock(password):
                try:
                    signature = private_key.sign(message, hash=PGPy.constants.HashAlgorithm.SHA512)
                    pgp_message |= signature
                except Exception:
                    return jsonify({'message': 'Could not sign message'}), 400
        except PGPy.errors.PGPDecryptionError:
            return jsonify({'message': 'Could not unlock private key. Is your password correct?'}), 400
    else:
        signature = private_key.sign(message, hash=PGPy.constants.HashAlgorithm.SHA512)
        pgp_message |= signature

    return jsonify({'output': str(pgp_message)})


@app.route('/api/verify-message', methods=['POST'])
def verify_message():
    data = request.json

    message = str(data.get('message'))
    keyId = int(data.get('publicKey'))

    key = Key.query.filter_by(id=keyId).first()
    if not key:
        return jsonify({'message': 'Public key not found'}), 404
    
    stripped_message_lines = [line.strip() for line in message.splitlines()]
    stripped_message = '\n'.join(stripped_message_lines)

    try:
        pgp_message = PGPy.PGPMessage.from_blob(stripped_message)
        if not pgp_message.is_signed:
            return jsonify({'message': 'Message is not signed'}), 400
    except ValueError:
        return jsonify({'message': 'Invalid message'}), 400

    # Verify the message
    public_key, _ = PGPy.PGPKey.from_blob(key.public_key)

    try:
        if public_key.verify(pgp_message):
            return jsonify({'message': 'Signature is valid'})
        else:
            return jsonify({'message': 'Signature is invalid'}), 400
    except PGPy.errors.PGPError:
        return jsonify({'message': 'Signature is invalid'}), 400
    

@app.route('/api/delete-key', methods=['POST'])
def delete_key():
    data = request.json
    keyId = int(data.get('id'))

    key = Key.query.filter_by(id=keyId).first()
    if not key:
        return jsonify({'message': 'Key not found'}), 404

    db.session.delete(key)
    db.session.commit()

    return jsonify({'message': 'Key deleted successfully!'})