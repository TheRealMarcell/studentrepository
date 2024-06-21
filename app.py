'''
app.py contains all of the server application
this is where you'll find all of the get/post request handlers
the socket event handlers are inside of socket_routes.py
'''

from flask import Flask, render_template, request, abort, url_for, redirect, flash, jsonify,session
from flask_bcrypt import Bcrypt
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from base64 import urlsafe_b64encode, urlsafe_b64decode
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from flask_socketio import SocketIO
import db
import secrets
from models import User, Friends, FriendshipStatus,EncryptedMessage,Room
from hashlib import sha256
from sqlalchemy.orm import Session
from sqlalchemy import create_engine
from sqlalchemy.exc import SQLAlchemyError
import bcrypt
import json
from flask_socketio import SocketIO, emit

import logging

# this turns off Flask Logging, uncomment this to turn off Logging
# log = logging.getLogger('werkzeug')
# log.setLevel(logging.ERROR)



app = Flask(__name__)

# secret key used to sign the session cookie
app.config['SECRET_KEY'] = secrets.token_hex()
socketio = SocketIO(app)
bcrypt = Bcrypt(app)
engine = create_engine('sqlite:///main.db', echo=True)


# don't remove this!!

import socket_routes
room_manager = Room()

@app.route("/logout/<username>")
def logout(username):
    return render_template("index.jinja")


# index page (initial landing page)
@app.route("/")
def index():
    session["user"] = None

    return render_template("index.jinja")

# handles a get request to the signup page
@app.route("/signup")
def signup():
    return render_template("signup.jinja")

# handles a post request when the user clicks the signup button
@app.route("/signup/user", methods=["POST"])
def signup_user():
    if not request.is_json:
        abort(404)
    # XSS prevention by sanitising on server-side
    username = request.json.get("username")
    password = request.json.get("password")
    role = request.json.get("role")
    print(role)
    username = xss_prevention(username)
    password = xss_prevention(password)

    # generate a salt (random string), concatenate the plaintext password with the salt
    salt = secrets.token_hex(8)
    salted_password = password + salt

    # SHA256 hashing of the salted password on server-side
    hashed_password = sha256(salted_password.encode('utf-8')).hexdigest()

    if db.get_user(username) is None:
        db.insert_user(username, hashed_password, salt, role)
        return url_for('login', username=username)
    return "Error: User already exists!"

# login page
@app.route("/login")
def login():    
    return render_template("login.jinja")

@app.route("/login/user", methods=["POST"])
def login_user():
    if not request.is_json:
        abort(404)

    # XSS prevention by sanitising on server-side
    username = request.json.get("username")
    password = request.json.get("password")
    username = xss_prevention(username)
    password = xss_prevention(password)

    # hash the password with sha256
    password_in_db = db.get_user(username).password
    salt_in_db = db.get_user(username).salt
    salted_password = password + salt_in_db

    # SHA256 hashing of the salted password on server-side
    hashed_password = sha256(salted_password.encode('utf-8')).hexdigest()

    user =  db.get_user(username)
    if user is None:
        return "Error: User does not exist!"

    if hashed_password != password_in_db:
        return "Error: Password does not match!"

    # session handling
    session["user"] = username
    return url_for('home', username=request.json.get("username"))

# handler when a "404" error happens
@app.errorhandler(404)
def page_not_found(_):
    return render_template('404.jinja'), 404

user_list = db.get_all_user()

# Home page (friends_list page), the initial landing page after logging in.
@app.route("/home", methods=['GET', 'POST'])
def home():
    username = request.args.get("username")
    # verify that the user is in current session
    if "user" in session:
        user = session["user"]
        if user != username:
            # if user is trying to access a webpage not native to their session
            abort(404)
    else:
        # if user is not in session, they should login first
        return redirect(url_for("login"))

    if not username:
        flash("Username is required.")
        return redirect(url_for('login'))

    page = "home"
    user_list = db.get_all_user()
    friends_list = db.get_friends_list(username)
    role = db.get_role(username)
    mute_status = db.get_mute_status(username)
    print(role)
    friends_status = []
    friends_roles = []

    for friend in friends_list:
        status = db.get_status(friend)
        friend_role = db.get_role(friend)
        friends_status.append(status)
        friends_roles.append(friend_role)
    
    return render_template("friends.jinja", username=username, users=user_list, friends_list=friends_list, role=role, friends_as_json=json.dumps(friends_list), status_list = friends_status, role_list=friends_roles, page=page, mute_status = mute_status)


# Room page when a user wants to chat with a friend
@app.route("/room", methods=['GET', 'POST'])
def room():
    username = request.args.get("username")
    friend = request.args.get('friend')
    return render_template("room.jinja", username=username, friend=friend)

@app.route('/home/article/<id>/<username>/<role>', methods=['GET', 'POST'])
def article(id, username, role):
    article_content = db.get_article_by_id(id)
    return render_template("article.jinja", article=article_content, username=username, role=role)

@app.route("/rooms/<username>", methods=['GET', 'POST'])
def rooms(username):
    if not username:
        flash("Username is required.")
        return redirect(url_for('login'))

    page = "rooms"
    user_list = db.get_all_user()
    friends_list = db.get_friends_list(username)
    role = db.get_role(username)
    friends_status = []
    friends_roles = []
    print(role)
    for friend in friends_list:
        status = db.get_status(friend)
        friend_role = db.get_role(friend)
        
        friends_status.append(status)
        friends_roles.append(friend_role)

    return render_template("rooms.jinja", username=username, users=user_list, friends_list=friends_list, role=role, friends_as_json=json.dumps(friends_list), status_list=friends_status, role_list=friends_roles, page=page)

@app.route('/chatroom/<room_id>', methods=['GET'])
def chatroom(room_id):
    if not room_id:
        return "Room ID is missing", 400
    room_name = get_room_name(room_id) 
    return render_template('chatroom.jinja', room_id=room_id, room_name=room_name)

def get_room_name(room_id):
    return f"Room {room_id}"


@app.route('/home/fetch_friend_requests', methods=['GET'])
def fetch_friend_requests():
    # username = session.get("username")

    username = request.args.get("username")
    if not username:
        return jsonify({"error": "You must be logged in to view friend requests"}), 401

    friend_requests = db.get_received_friend_requests(username)
    requests_data = [{'fromUser': req.person1, 'id': req.connection_id} for req in friend_requests]
    
    return jsonify({"requests": requests_data}), 200


@app.route('/home/send_fr', methods=['POST'])
def send_friend_request():
    if not request.is_json:
        return jsonify({"message": "Invalid request"}), 400

    data = request.get_json()
    sender_username = data.get('sender')
    receiver_username = data.get('receiver')

    if not all([sender_username, receiver_username]):
        return jsonify({"message": "Missing data"}), 400

    try:
        if are_already_friends_or_pending(sender_username, receiver_username):
            return jsonify({"message": "Already friends or request pending"}), 409

        success = db.add_friend_request(sender_username, receiver_username)
        if success:
            return jsonify({"message": "Friend request sent"}), 200
        else:
            return jsonify({"message": "Receiver does not exist"}), 404
        
    except Exception as e:
        return jsonify({"message": f"Internal server error: {str(e)}"}), 500


@app.route('/accept-friend-request/<int:request_id>', methods=['POST'])
def accept_friend_request(request_id):
    if db.accept_friend_request(request_id):
        return jsonify({"message": "Friend request accepted"}), 200
    else:
        return jsonify({"message": "Could not accept friend request"}), 500


@app.route('/reject-friend-request/<int:request_id>', methods=['POST'])
def reject_friend_request(request_id):
    if db.reject_friend_request(request_id):
        return jsonify({"message": "Friend request rejected"}), 200
    else:
        return jsonify({"message": "Could not reject friend request"}), 500

def are_already_friends_or_pending(user1, user2):
    existing = db.get_received_friend_requests(user2)
    for request in existing:
        if (request.person1 == user1 or request.person2 == user1) and \
           (request.status == FriendshipStatus.PENDING or request.status == FriendshipStatus.ACCEPTED):
            return True
    return False

def search_friend(friend):
    user_list = db.get_all_user()  # Update to fetch user list dynamically
    for i in user_list:
        if friend == i.username:
            return True
    return False

def get_friend(user):
    friends_list = db.get_friends_list(user)  # Update to fetch friend list dynamically
    list_of_friends = []
    for connection in friends_list:
        list_of_friends.append(connection)
    return list_of_friends

def xss_prevention(string):
    bad_chars = '$*+.-/"<>'
    for char in bad_chars:
        string = string.replace(char, "")
    return string


def get_kdf(salt):
    return PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )

def encrypt_message(key, plaintext):
    cipher = Cipher(algorithms.AES(key), modes.GCM())
    encryptor = cipher.encryptor()
    encrypted_text = encryptor.update(plaintext.encode()) + encryptor.finalize()
    return encrypted_text, encryptor.tag


def decrypt_message(key, tag, encrypted_text):
    cipher = Cipher(algorithms.AES(key), modes.GCM(tag))
    decryptor = cipher.decryptor()
    return decryptor.update(encrypted_text) + decryptor.finalize()

@app.route('/encrypt', methods=['POST'])
def encrypt():
    data = request.json
    password = data['password']
    plaintext = data['plaintext']
    

    salt = bcrypt.gensalt()
    key = get_kdf(salt).derive(password.encode())
    

    encrypted_text, tag = encrypt_message(key, plaintext)
    

    return jsonify({
        'encrypted': urlsafe_b64encode(encrypted_text).decode(),
        'tag': urlsafe_b64encode(tag).decode(),
        'salt': urlsafe_b64encode(salt).decode()
    })


online_users = {}

def is_receiver_online(receiver_username):
    return online_users.get(receiver_username, False)

def insert_offline_message(sender_username, receiver_username, message):
    try:
        with Session(engine) as session:
            encrypted_message = EncryptedMessage(
                sender_username=sender_username,
                receiver_username=receiver_username,
                encrypted_text=message,  
                is_offline=True 
            )
            session.add(encrypted_message)
            session.commit()
            print("Offline message stored successfully.")
            return True
    except SQLAlchemyError as e:
        print(f"Database error: {e}")
        return False


@app.route('/send_message', methods=['POST'])
def send_message():
    data = request.get_json()
    username = data['username']
    password = data['password']
    plaintext = data['message']
    receiver = data['receiver']

    user = db.get_user(username)
    if not user:
        return jsonify({"error": "User not found"}), 404

    salted_password = password + user.salt
    hashed_password = sha256(salted_password.encode('utf-8')).hexdigest()
    
    if hashed_password != user.password:
        return jsonify({"error": "Authentication failed"}), 403

    if not is_receiver_online(receiver):

        success = db.insert_offline_message(username, receiver, plaintext)
        if success:
            return jsonify({"message": "Message stored for later delivery"}), 200
        else:
            return jsonify({"error": "Failed to store message"}), 500
    else:

        salt = secrets.token_hex(16)  
        key = get_kdf(salt.encode()).derive(password.encode())
        encrypted_message, tag = encrypt_message(key[:32], plaintext)  
        db.insert_encrypted_message(username, receiver, encrypted_message, tag, salt)
        return jsonify({"message": "Message sent successfully", "tag": urlsafe_b64encode(tag).decode(), "salt": salt}), 200
    

@app.route('/get_offline_messages', methods=['GET'])
def get_offline_messages():
    username = session.get('user')
    if not username:
        return jsonify({'error': 'User not authenticated'}), 401

    try:
        encrypted_messages = db.get_encrypted_messages(username)
        decrypted_messages = []
        for msg in encrypted_messages:
            salt = urlsafe_b64decode(msg.encryption_salt.encode())
            key = get_kdf(salt).derive(session['user_password'].encode())  
            tag = urlsafe_b64decode(msg.encryption_tag)
            encrypted_text = urlsafe_b64decode(msg.encrypted_text)
            decrypted_text = decrypt_message(key, tag, encrypted_text)
            decrypted_messages.append({'text': decrypted_text.decode('utf-8'), 'sender': msg.sender_username})

        return jsonify({'messages': decrypted_messages}), 200
    except Exception as e:
        return jsonify({'error': 'Failed to decrypt messages', 'details': str(e)}), 500

@app.route('/home/delete_fr', methods=['POST'])
def delete_friend():
    if not request.is_json:
        return jsonify({"message": "Invalid request"}), 400

    data = request.get_json()
    username = data.get('username')
    friend = data.get('friend')

    if not all([username, friend]):
        return jsonify({"message": "Missing data"}), 400

    try:
        success = db.delete_friend(username, friend)
        print(success)
        if success:
            return jsonify({"message": "Friend deleted"}), 200
        else:
            return None
        
    except Exception as e:
        print(e)
        return jsonify({"message": f"Internal server error: {str(e)}"}), 500
    
@app.route('/join-room', methods=['POST'])
def join_room():
    data = request.get_json()
    room_id = data.get('room_id')
    username = data.get('username')  

    if not all([room_id, username]):
        return jsonify({"message": "Missing data", "success": False}), 400

    try:
        success = room_manager.join_room(username, int(room_id))
        if success:
            return jsonify({"message": "User added to room", "success": True}), 200
        else:
            return jsonify({"message": "User already in room", "success": False}), 400

    except Exception as e:
        print(e)
        return jsonify({"message": f"Internal server error: {str(e)}", "success": False}), 500

@app.route('/get-room-members', methods=['GET'])
def get_room_members():
    room_id = request.args.get('room_id')

    if not room_id:
        return jsonify({"message": "Missing room id"}), 400

    try:
        members = room_manager.get_room_members(int(room_id))
        return jsonify({"members": members}), 200

    except Exception as e:
        print(e)
        return jsonify({"message": f"Internal server error: {str(e)}"}), 500



if __name__ == '__main__':
    app.run(ssl_context=("./certs/localhost.crt", "./certs/localhost.key"))



