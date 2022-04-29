import os
import urllib.request
import ipfshttpclient
from my_constants import app, db, userData, doctorData
import pyAesCrypt
from flask import Flask, flash, request, redirect, render_template, url_for, jsonify, make_response
from flask_socketio import SocketIO, send, emit
from werkzeug.utils import secure_filename
import socket
import pickle
from blockchain import Blockchain
import pyqrcode
import png
from pyzbar.pyzbar import decode
from PIL import Image

# The package requests is used in the 'hash_user_file' and 'retrieve_from hash' functions to send http post requests.
# Notice that 'requests' is different than the package 'request'.
# 'request' package is used in the 'add_file' function for multiple actions.

socketio = SocketIO(app)
blockchain = Blockchain()

def __UserauthLogin__(emailId_, password_):
   emailId_ = str(emailId_)
   password_ = str(password_)
   token = userData.query.filter(userData.EmailId.like(emailId_)).filter(userData.Password.like(password_)).first()
   if token:
      return True
   return False

def __DoctorauthLogin__(emailId_, password_):
   emailId_ = str(emailId_)
   password_ = str(password_)
   token = doctorData.query.filter(doctorData.EmailId.like(emailId_)).filter(doctorData.Password.like(password_)).first()
   if token:
      return True
   return False

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

def append_file_extension(uploaded_file, file_path):
    file_extension = uploaded_file.filename.rsplit('.', 1)[1].lower()
    user_file = open(file_path, 'a')
    user_file.write('\n' + file_extension)
    user_file.close()

def decrypt_file(file_path, file_key):
    encrypted_file = file_path + ".aes"
    os.rename(file_path, encrypted_file)
    pyAesCrypt.decryptFile(encrypted_file, file_path,  file_key, app.config['BUFFER_SIZE'])

def encrypt_file(file_path, file_key):
    pyAesCrypt.encryptFile(file_path, file_path + ".aes",  file_key, app.config['BUFFER_SIZE'])

def hash_user_file(user_file, file_key):
    encrypt_file(user_file, file_key)
    encrypted_file_path = user_file + ".aes"
    client = ipfshttpclient.connect('/dns/ipfs.infura.io/tcp/5001/https')
    response = client.add(encrypted_file_path)
    file_hash = response['Hash']
    return file_hash

def retrieve_from_hash(file_hash, file_key):
    client = ipfshttpclient.connect('/dns/ipfs.infura.io/tcp/5001/https')
    file_content = client.cat(file_hash)
    file_path = os.path.join(app.config['DOWNLOAD_FOLDER'], file_hash)
    user_file = open(file_path, 'ab+')
    user_file.write(file_content)
    user_file.close()
    decrypt_file(file_path, file_key)
    with open(file_path, 'rb') as f:
        lines = f.read().splitlines()
        last_line = lines[-1]
    user_file.close()
    file_extension = last_line
    saved_file = file_path + '.' + file_extension.decode()
    os.rename(file_path, saved_file)
    print(saved_file)
    return saved_file

@app.route('/', methods = ['POST', 'GET'])
def login():
    if request.method == 'POST':
       username_ = request.form.get("Name")
       emailId_ = request.form.get("Email")
       password_ = request.form.get("Password")
       if not username_:
            print(emailId_, password_)
            resp = make_response(redirect(url_for('home')))
            if __UserauthLogin__(emailId_, password_):
                resp.set_cookie('Authentication', 'True')
                return resp 
            else:
                resp.set_cookie('Authentication', 'False') 
            return render_template('login.html')
       else:
            print(username_, emailId_, password_)
            newUser = userData(Username = username_, EmailId = emailId_, Password = password_)
            db.session.add(newUser)
            db.session.commit()
            return render_template('login.html')
    return render_template('login.html')

@app.route('/home')
def home():
    Authentication = request.cookies.get('Authentication')
    if Authentication == "True":  
        return render_template('index.html')
    else:
        return redirect(url_for('login'))

@app.route('/logout')
def logout(): 
    Authentication = request.cookies.get('Authentication')
    if Authentication == "True":  
        resp = make_response(redirect(url_for('login')))
        resp.set_cookie('Authentication', 'False')
        return resp
    return redirect(url_for('login'))

@app.route('/upload')
def upload():
    return render_template('upload.html' , message = "Welcome!")

@app.route('/download')
def download():
    Authentication = request.cookies.get('Authentication')
    if Authentication == "True":  
        return render_template('download.html' , message = "Welcome!")
    else:
        return redirect(url_for('login'))

@app.route('/connect_blockchain')
def connect_blockchain():
    Authentication = request.cookies.get('Authentication')
    if Authentication == "True":  
        is_chain_replaced = blockchain.replace_chain()
        print(is_chain_replaced)
        return render_template('connect_blockchain.html', chain = blockchain.chain, nodes = len(blockchain.nodes))
    else:
        return redirect(url_for('login'))

@app.errorhandler(413)
def entity_too_large(e):
    return render_template('upload.html' , message = "Requested Entity Too Large!")

@app.route('/add_file', methods=['POST'])
def add_file():
    Authentication = request.cookies.get('Authentication')
    if Authentication == "True":  
        is_chain_replaced = blockchain.replace_chain()

        if is_chain_replaced:
            print('The nodes had different chains so the chain was replaced by the longest one.')
        else:
            print('All good. The chain is the largest one.')

        if request.method == 'POST':
            error_flag = True
            if 'file' not in request.files:
                message = 'No file part'
            else:
                user_file = request.files['file']

                if user_file.filename == '':
                    message = 'No file selected for uploading'

                if user_file and allowed_file(user_file.filename):
                    error_flag = False
                    filename = secure_filename(user_file.filename)
                    #file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                    file_path = app.config['UPLOAD_FOLDER'] + "\\" + filename
                    user_file.save(file_path)
                    append_file_extension(user_file, file_path)
                    doctorId = request.form['doctorId']
                    patientId = request.form['patientId']
                    encryptionKey = request.form['encryptionKey']
                    recieptId = request.form['recieptId']

                    try:
                        hashed_output1 = hash_user_file(file_path, encryptionKey)
                        index = blockchain.add_file(doctorId, patientId, recieptId, hashed_output1)
                    except Exception as err:
                        message = str(err)
                        print(message)
                        error_flag = True
                        if "ConnectionError:" in message:
                            message = "Gateway down or bad Internet!"

                else:
                    error_flag = True
                    message = 'Allowed file types are txt, pdf, png, jpg, jpeg, gif'
        
            if error_flag == True:
                return render_template('upload.html' , message = message)
            else:
                code = pyqrcode.create(hashed_output1)
                code.svg(app.config['QRCODE_FILE'], scale = 8)
                return render_template('upload.html' , message = "static/img/temp/qrcode.svg")
    else:
        return redirect(url_for('login'))

@app.route('/retrieve_file', methods=['POST'])
def retrieve_file():
    Authentication = request.cookies.get('Authentication')
    if Authentication == "True":  
        is_chain_replaced = blockchain.replace_chain()

        if is_chain_replaced:
            print('The nodes had different chains so the chain was replaced by the longest one.')
        else:
            print('All good. The chain is the largest one.')

        if request.method == 'POST':

            error_flag = True

            if request.form['file_hash'] == '' and request.files['file'] == '':
                message = 'No file hash entered.'
            elif request.form['file_key'] == '':
                message = 'No file key entered.'
            else:
                error_flag = False
                file_key = request.form['file_key']
                #file_hash = request.form['file_hash']
                if 'file' not in request.files:
                    file_hash = request.form['file_hash']
                else:
                    user_file = request.files['file']  
                print(user_file)
                if user_file:
                    file_hash = decode(Image.open(user_file))
                    file_hash = file_hash[0].data.decode('ascii')
                else:
                    file_hash = request.form['file_hash']          
                try:
                    file_path = retrieve_from_hash(file_hash, file_key)
                except Exception as err:
                    message = str(err)
                    error_flag = True
                    if "ConnectionError:" in message:
                        message = "Gateway down or bad Internet!"



            if error_flag == True:
                return render_template('download.html' , message = message)
            else:
                return render_template('download.html' , message = "File successfully downloaded")
    else:
        return redirect(url_for('login'))

# Getting the full Blockchain
@app.route('/get_chain', methods = ['GET'])
def get_chain():
    Authentication = request.cookies.get('Authentication')
    if Authentication == "True":  
        response = {'chain': blockchain.chain,
                    'length': len(blockchain.chain)}
        return jsonify(response), 200
    else:
        return redirect(url_for('login'))

@socketio.on('connect')
def handle_connect():
    print('Client connected')
    print(request)

@socketio.on('add_client_node')
def handle_node(client_node):
    print(client_node)
    blockchain.nodes.add(client_node['node_address'])
    emit('my_response', {'data': pickle.dumps(blockchain.nodes)}, broadcast = True)

@socketio.on('remove_client_node')
def handle_node(client_node):
    print(client_node)
    blockchain.nodes.remove(client_node['node_address'])
    emit('my_response', {'data': pickle.dumps(blockchain.nodes)}, broadcast = True)

@socketio.on('disconnect')
def handle_disconnect():
    print('Client disconnected')
    print(request)

if __name__ == '__main__':
    if not os.path.exists("userData.sqlite3"):
        db.create_all()
    socketio.run(app, host = '127.0.0.1', port= 5511, debug = True)