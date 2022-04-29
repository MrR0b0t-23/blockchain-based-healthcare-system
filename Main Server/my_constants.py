from flask import Flask
from flask_sqlalchemy import SQLAlchemy

UPLOAD_FOLDER = 'uploads'
DOWNLOAD_FOLDER = 'downloads'
QRCODE_FILE = 'static\\img\\temp\\qrcode.svg'

app = Flask(__name__)
app.secret_key = "secret key"
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['DOWNLOAD_FOLDER'] = DOWNLOAD_FOLDER
app.config['QRCODE_FILE'] = QRCODE_FILE
app.config['ALLOWED_EXTENSIONS'] = set(['txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'])
app.config['BUFFER_SIZE'] = 64 * 1024
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024

app.config['DEBUG'] = True
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_DATABASE_URI'] = "sqlite:///userData.sqlite3"
db = SQLAlchemy(app)

class userData(db.Model):
    __tablename__ = 'User_Database'

    UserId = db.Column(db.Integer, primary_key=True)
    Username = db.Column(db.String(80), nullable=False)
    EmailId = db.Column(db.String(80), nullable=False)
    Password = db.Column(db.String(80), nullable=False)

    def __init__ (self, Username, EmailId, Password):
        self.Username= Username
        self.EmailId = EmailId
        self.Password = Password

class doctorData(db.Model):
    __tablename__ = 'Doctor_Database'

    DoctorId = db.Column(db.Integer, primary_key=True)
    Doctorname = db.Column(db.String(80), nullable=False)
    EmailId = db.Column(db.String(80), nullable=False)
    Password = db.Column(db.String(80), nullable=False)

    def __init__ (self, Username, EmailId, Password):
        self.Username= Username
        self.EmailId = EmailId
        self.Password = Password