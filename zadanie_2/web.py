import os

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from flask import Flask, Response, request, jsonify
from cryptography.hazmat.primitives import hashes

from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///data.db'

db = SQLAlchemy(app)

'''
    Tabulka pre pouzivatelov:
    - id: jedinecne id pouzivatela
    - username: meno pouzivatela
    - public_key: verejny kluc pouzivatela

    Poznamka: mozete si lubovolne upravit tabulku podla vlastnych potrieb
'''
class User(db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    public_key = db.Column(db.String(120), unique=True, nullable=False)

    def __repr__(self):
        return f'<User {self.username}>'

with app.app_context():
    db.create_all()

'''
    API request na generovanie klucoveho paru pre pozuivatela <user>
    - user: meno pouzivatela, pre ktoreho sa ma vygenerovat klucovy par
    - API volanie musi vygenerovat klucovy par pre pozuivatela <user> a verejny kluc ulozit do databazy
    - API volanie musi vratit privatny kluc pouzivatela <user> (v binarnom formate)

    ukazka: curl 127.0.0.1:1337/api/gen/ubp --output ubp.key
'''
@app.route('/api/gen/<user>', methods=['GET'])
def generate_keypair(user):
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    public_key = private_key.public_key()
    # Sériovanie verejného kľúča pre uloženie do simulovanej databázy
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    # Kontrola, či používateľ už existuje
    if User.query.filter_by(username=user).first() is not None:
        return Response("User already exists.", status=400)

    new_user = User(username=user, public_key=public_pem)
    db.session.add(new_user)
    db.session.commit()

    # Sériovanie privátneho kľúča pre odoslanie klientovi
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )

    return Response(private_pem, content_type='application/octet-stream')


'''
    API request na zasifrovanie suboru pre pouzivatela <user>
    user: meno pouzivatela, ktoremu sa ma subor zasifrovat
    vstup: subor, ktory sa ma zasifrovat

    ukazka: curl -X POST 127.0.0.1:1337/api/encrypt/ubp -H "Content-Type: application/octet-stream" --data-binary @file.pdf --output encrypted.bin
'''
@app.route('/api/encrypt/<user>', methods=['POST'])
def encrypt_file(user):


    user_record = User.query.filter_by(username=user).first()
    if not user_record:
        return Response("User not found.", status=404)

    public_key = serialization.load_pem_public_key(
        user_record.public_key,
        backend=default_backend()
    )

    # Vytvorenie náhodného symetrického kľúča K
    sym_key = os.urandom(32)  # 256-bitový kľúč pre AES
    iv = os.urandom(16)  # Inicializačný vektor pre AES

    # Šifrovanie obsahu súboru
    file_content = request.data  # Načítanie obsahu z požiadavky
    cipher = Cipher(algorithms.AES(sym_key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    # Padding pre obsah
    block_size = algorithms.AES.block_size // 8  # Prevod na bajty
    padding_length = block_size - len(file_content) % block_size

    padded_content = file_content + bytes([padding_length] * padding_length)
    encrypted_content = encryptor.update(padded_content) + encryptor.finalize()

    # Šifrovanie symetrického kľúča K verejným kľúčom používateľa
    encrypted_sym_key = public_key.encrypt(
        sym_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Vytvorenie výsledného formátu
    # Prvý blok: Dĺžka zašifrovaného kľúča
    # Druhý blok: Zašifrovaný kľúč
    # Tretí blok: IV
    # Štvrtý blok: Zašifrovaný obsah

    result = (
        len(encrypted_sym_key).to_bytes(4, 'big') +
        encrypted_sym_key +
        iv +
        encrypted_content
    )

    return Response(result, content_type='application/octet-stream')


'''
    API request na desifrovanie
    - vstup: zasifrovany subor ktory sa ma desifrovat a privatny kluc pouzivatela

    ukazka: curl -X POST 127.0.0.1:1337/api/decrypt -F "file=@encypted.bin" -F "key=@ubp.key" --output decrypted.pdf
'''
@app.route('/api/decrypt', methods=['POST'])
def decrypt_file():


    file = request.files.get('file')
    key = request.files.get('key')

    return Response(b'\xff', content_type='application/octet-stream')


'''
    API request na podpisanie dokumentu
    - vstup: subor ktory sa ma podpisat a privatny kluc

    ukazka: curl -X POST 127.0.0.1:1337/api/sign -F "file=@document.pdf" -F "key=@ubp.key" --output signature.bin
'''
@app.route('/api/sign', methods=['POST'])
def sign_file():
    '''
        TODO: implementovat
    '''

    file = request.files.get('file')
    key = request.files.get('key')

    return Response(b'\xff', content_type='application/octet-stream')


'''
    API request na overenie podpisu pre pouzivatela <user>
    - vstup: digitalny podpis a subor

    ukazka: curl -X POST 127.0.0.1:1337/api/verify/upb -F "file=@document.pdf" -F "signature=@signature.bin" --output signature.bin
'''
@app.route('/api/verify/<user>', methods=['POST'])
def verify_signature(user):
    '''
        TODO: implementovat
    '''

    file = request.files.get('file')
    signature = request.files.get('signature')

    return jsonify({'verified': False})



'''
    API request na zasifrovanie suboru pre pouzivatela <user> (verzia s kontrolou integrity)
    user: meno pouzivatela, ktoremu sa ma subor zasifrovat
    vstup: subor, ktory sa ma zasifrovat

    ukazka: curl -X POST 127.0.0.1:1337/api/encrypt/ubp -H "Content-Type: application/octet-stream" --data-binary @file.pdf --output encrypted_file.bin
'''
@app.route('/api/encrypt2/<user>', methods=['POST'])
def encrypt_file2(user):
    '''
        TODO: implementovat
    '''

    return Response(b'\xff', content_type='application/octet-stream')


'''
    API request na desifrovanie (verzia s kontrolou integrity)
    - vstup: zasifrovany subor ktory sa ma desifrovat a privatny kluc pouzivatela

    ukazka: curl -X POST 127.0.0.1:1337/api/decrypt -F "file=@encypted_file.bin" -F "key=@ubp.key" --output decrypted_file.pdf
'''
@app.route('/api/decrypt2', methods=['POST'])
def decrypt_file2():
    '''
        TODO: implementovat
    '''

    file = request.files.get('file')
    key = request.files.get('key')

    return Response(b'\xff', content_type='application/octet-stream')



if __name__ == '__main__':
    app.run(port=1337)