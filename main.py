# IMPORTS --------------------------------------------------------------------------------------------------------------
import logging
import os
import bcrypt
import json

from flask import Flask, request, Response
from flask_sqlalchemy import SQLAlchemy
from uuid import uuid4
from functools import wraps

from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

# SETUP ----------------------------------------------------------------------------------------------------------------

app = Flask(__name__)

limiter = Limiter(
    app,
    key_func=get_remote_address,
    global_limits=["200 per day", "25 per hour"]
)

# DATABASE STUFF -------------------------------------------------------------------------------------------------------

app.config['SQLALCHEMY_DATABASE_URI'] = os.environ['SQLALCHEMY_DATABASE_URI']
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)


# helper function just to be safe in case commit() fails
def commit_db():
    try:
        db.session.commit()
    except Exception as e:
        logging.exception(e)
        db.session.rollback()
        db.session.flush()  # reset non-commited.add()


# AUTH STUFF -----------------------------------------------------------------------------------------------------------


def check_auth(token):
    return User.query.filter(User.token == token).count()  # if there doesnt exist an entry then not logged in


def authenticate():
    return Response(
        'Could not verify your access level for that URL.\n'
        'You have to login with proper credentials', 401,
        {'WWW-Authenticate': 'Basic realm="Login Required"'})


def requires_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.args.get('token')
        if not auth or not check_auth(auth):
            return authenticate()
        return f(*args, **kwargs)

    return decorated


# MODELS ---------------------------------------------------------------------------------------------------------------

class User(db.Model):
    __tablename__ = "user"
    id = db.Column(db.String(100), primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    token = db.Column(db.String(100))
    readingLists = db.relationship('ReadingList', backref='user', lazy='dynamic')

    def __init__(self, **kwargs):
        self.id = str(uuid4())
        self.email = kwargs['email']
        self.password = kwargs['password']
        self.token = kwargs['token']
        self.readingLists = []

    @classmethod
    def get_by_id(cls, _id):
        return cls.query.filter(cls.id == _id).first()

    @classmethod
    def get_by_email(cls, email):
        return cls.query.filter(cls.email == email).first()

    @classmethod
    def get_by_token(cls, token):
        return cls.query.filter(cls.token == token).first()

# ROUTES ---------------------------------------------------------------------------------------------------------------

    @app.route('/create-account', methods=['POST'])
    def create_account_email():
        data = json.loads(request.data.decode('utf-8'))
        if User.get_by_email(data['email']):
            return "Email already in use", 400
        data['password'] = bcrypt.hashpw(data['password'].encode('utf-8'), bcrypt.gensalt())
        # design decision to have user auto logged on account creation
        data['token'] = str(uuid4())
        user = User(**data)
        db.session.add(user)
        commit_db()
        return Response(response=json.dumps({'token': str(user.token)}), status=200)

    @app.route('/login', methods=['POST'])
    def login():
        data = json.loads(request.data.decode('utf-8'))
        user = User.get_by_email(data['email'])
        if not user:
            return "User not found", 404
        if user.token:
            return "Already logged in", 400
        if bcrypt.hashpw(data['password'].encode('utf-8'), user.password.encode('utf-8')) == user.password:
            user.token = str(uuid4())
            commit_db()
            return Response(response=json.dumps({'token': user.token}), status=200)
        return 'Bad password', 401

    @app.route('/logout', methods=['GET'])
    @requires_auth
    def logout():
        user = User.get_by_token(request.args.get('token'))
        # previously generated token is now no longer valid
        user.token = None
        commit_db()
        return "Logged out", 200


# MAIN -----------------------------------------------------------------------------------------------------------------


if __name__ == '__main__':
    app.run(host='127.0.0.1', port=8080, debug=True)
