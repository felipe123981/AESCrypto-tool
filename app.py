import os
import secrets
import logging
from flask import Flask, request, render_template, flash, redirect, send_from_directory, Markup
from werkzeug.utils import secure_filename
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

# Configuração de Logs
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

UPLOAD_FOLDER = 'files'
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'zip', 'jpg', 'jpeg', 'png', 'docx', 'rar'}

app = Flask(__name__)
app.secret_key = 'super_secret_key'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

# Verifica se a extensão do arquivo é permitida
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Deriva uma chave segura a partir de uma senha
def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100_000,
        backend=default_backend()
    )
    return kdf.derive(password.encode('utf-8'))

# Função para criptografar um arquivo usando AES-GCM
def encrypt_file_AES_GCM(input_file, output_encrypted_file, key):
    nonce = secrets.token_bytes(12)  # Gera um nonce aleatório (12 bytes para AES-GCM)
    with open(input_file, 'rb') as file:
        data = file.read()

    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(data) + encryptor.finalize()

    # Salva o nonce, tag e dados criptografados no arquivo
    with open(output_encrypted_file, 'wb') as file:
        file.write(nonce)  # Salva o nonce
        file.write(encryptor.tag)  # Salva o tag de autenticação
        file.write(ciphertext)  # Salva os dados criptografados

# Função para descriptografar um arquivo usando AES-GCM
def decrypt_file_AES_GCM(input_encrypted_file, output_decrypted_file, key):
    with open(input_encrypted_file, 'rb') as file:
        nonce = file.read(12)  # Lê o nonce (12 bytes)
        tag = file.read(16)  # Lê o tag de autenticação (16 bytes)
        ciphertext = file.read()  # Lê os dados criptografados

    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()

    # Salva os dados descriptografados
    with open(output_decrypted_file, 'wb') as file:
        file.write(decrypted_data)

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        file = request.files.get('file')
        password = request.form.get('password')

        if not file or not allowed_file(file.filename):
            logging.warning("Invalid or missing file.")
            flash("Invalid or missing file.", "error")
            return redirect(request.url)
        if not password:
            logging.warning("Password is required.")
            flash("Password is required.", "error")
            return redirect(request.url)

        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)

        # Deriva a chave segura
        salt = secrets.token_bytes(16)  # Gera um salt aleatório
        key = derive_key(password, salt)

        # Criptografa o arquivo
        encrypted_filename = filepath + '.aes'
        try:
            encrypt_file_AES_GCM(filepath, encrypted_filename, key)

            # Salva o salt usado para derivar a chave
            salt_file = encrypted_filename + '.salt'
            with open(salt_file, 'wb') as sf:
                sf.write(salt)

            os.remove(filepath)  # Remove o arquivo original após a criptografia

            logging.info(f"File encrypted successfully: {encrypted_filename}")
            flash(f"File encrypted successfully as {os.path.basename(encrypted_filename)}", "success")
        except Exception as e:
            logging.error(f"Encryption failed: {str(e)}")
            flash(f"Encryption failed: {str(e)}", "error")
            return redirect(request.url)

        return redirect(request.url)

    return render_template('index.html')

@app.route('/decrypt', methods=['POST'])
def decrypt():
    encrypted_file = request.files.get('encrypted_file')
    password = request.form.get('password')

    if not encrypted_file or not encrypted_file.filename.endswith('.aes'):
        logging.warning("Invalid or missing encrypted file.")
        flash("Invalid or missing encrypted file.", "error")
        return redirect('/')
    if not password:
        logging.warning("Password is required.")
        flash("Password is required.", "error")
        return redirect('/')

    encrypted_filename = secure_filename(encrypted_file.filename)
    encrypted_filepath = os.path.join(app.config['UPLOAD_FOLDER'], encrypted_filename)
    encrypted_file.save(encrypted_filepath)

    # Carrega o salt usado para derivar a chave
    salt_file = encrypted_filepath + '.salt'
    if not os.path.exists(salt_file):
        logging.warning("Salt file missing.")
        flash("Salt file missing.", "error")
        return redirect('/')

    with open(salt_file, 'rb') as sf:
        salt = sf.read()

    # Deriva a chave segura
    key = derive_key(password, salt)

    # Descriptografa o arquivo
    decrypted_filename = encrypted_filepath.replace('.aes', '.decrypted')
    try:
        decrypt_file_AES_GCM(encrypted_filepath, decrypted_filename, key)
        logging.info(f"File decrypted successfully: {decrypted_filename}")
        download_link = f"<a href='/download/{os.path.basename(decrypted_filename)}'>here</a>"
        flash(Markup(f"File decrypted successfully! You can download it {download_link}."), "success")
    except Exception as e:
        logging.error(f"Decryption failed: {str(e)}")
        flash(f"Decryption failed: {str(e)}", "error")
        return redirect('/')

    return redirect('/')

@app.route('/download/<filename>')
def download_file(filename):
    logging.info(f"Downloading file: {filename}")
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

if __name__ == '__main__':
    app.run(debug=False)  # Desativar debug em produção