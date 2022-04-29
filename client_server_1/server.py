import os
import urllib.request
import ipfshttpclient
from my_constants import app
import pyAesCrypt
from flask import Flask, flash, request, redirect, render_template, url_for, jsonify
from werkzeug.utils import secure_filename
from flask_socketio import SocketIO, send, emit
import socket
import pickle
from blockchain import Blockchain
import requests
import socketio
from pyzbar.pyzbar import decode
from PIL import Image 

# The package requests is used in the 'hash_user_file' and 'retrieve_from hash' functions to send http post requests.
# Notice that 'requests' is different than the package 'request'.
# 'request' package is used in the 'add_file' function for multiple actions.

sio = socketio.Client() 
client_ip = app.config['NODE_ADDR']
connection_status = False

blockchain = Blockchain()

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

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/home')
def home():
    return render_template('index.html')

@app.route('/download')
def download():
    return render_template('download.html' , message = "Welcome!")


@app.route('/retrieve_file', methods=['POST'])
def retrieve_file():

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

# Getting the full Blockchain
@app.route('/get_chain', methods = ['GET'])
def get_chain():
    response = {'chain': blockchain.chain,
                'length': len(blockchain.chain)}
    return jsonify(response), 200

@sio.event
def connect():
    print('connected to server')

@sio.event
def disconnect():
    print('disconnected from server')

@sio.event
def my_response(message):
    print(pickle.loads(message['data']))
    blockchain.nodes = pickle.loads(message['data'])


if __name__ == '__main__':
    app.run(host = client_ip['Host'], port= client_ip['Port'], debug=True)