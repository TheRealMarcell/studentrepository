'''
socket_routes
file containing all the routes related to socket.io
'''
from flask import Flask, request, jsonify
from flask_socketio import SocketIO, join_room, leave_room, emit

from flask_socketio import join_room, emit, leave_room
from flask import request
import json

from cryptography.fernet import Fernet

try:
    from __main__ import socketio
except ImportError:
    from app import socketio

from models import Room

import db


room = Room()


# when the client connects to a socket
# this event is emitted when the io() function is called in JS
@socketio.on('connect')
def connect():
    username = request.cookies.get("username")
    room_id = request.cookies.get("room_id")
    if room_id is None or username is None:
        return

    # socket automatically leaves a room on client disconnect
    # so on client connect, the room needs to be rejoined
    join_room(int(room_id))

    # emit("public-key", public_key, to=int(room_id))
    emit("incoming", (f"{username} has connected", "green"), to=int(room_id))

# event when client disconnects
# quite unreliable use sparingly
@socketio.on('disconnect')
def disconnect():
    username = request.cookies.get("username")
    room_id = request.cookies.get("room_id")
    if room_id is None or username is None:
        return
    emit("incoming", (f"{username} has disconnected", "red"), to=int(room_id))

# send message event handler
@socketio.on("send")
def send(username, message, room_id):
    emit("incoming", (f"{username}: {message}"), to=room_id)
    
# join room event handler
# sent when the user joins a room
def join(data):
    sender_name = data['sender_name']
    receiver_name = data['receiver_name']
    
    receiver = db.get_user(receiver_name)
    if receiver is None:
        return "Unknown receiver!"
    sender = db.get_user(sender_name)
    if sender is None:
        return "Unknown sender!"

    # Check if a room exists for the receiver; if not, create one
    room_id = room.get_room_id(receiver_name)
    if room_id is None:
        room_id = room.create_room(sender_name, receiver_name)
    
    # Add the sender to the room if they are not already in it
    if sender_name not in room.rooms[room_id]:
        room.join_room(sender_name, room_id)
        join_room(room_id)
        emit("incoming", (f"{sender_name} has joined the room. Now talking to {receiver_name}.", "green"), to=room_id)
    else:
        emit("incoming", (f"{sender_name} is already in the room.", "yellow"), to=room_id)

    return room_id

# leave room event handler
@socketio.on("leave")
def leave(data):
    username = data['username']
    room_id = data['room_id']
    
    if room_id in room.rooms and username in room.rooms[int(room_id)]:
        room.leave_room(username)
        leave_room(int(room_id))
        emit("incoming", (f"{username} has left the room.", "red"), to=int(room_id))



# receive public key handler
@socketio.on("send_key")
def send_key(public_key, room_id):
    emit("receive-key", public_key, to=room_id, include_self=False)

@socketio.on("is_room_ready")
def check_room(data):
    room_id = data['room_id']
    message = "Room is ready"
    if room_id in room.rooms and len(room.rooms[int(room_id)]) >= 2:
        emit("room_is_ready", message, to=int(room_id))



@socketio.on("delete_friend")
def delete_friend(username, friend_name):
    emit("update-friend", { "user": username, "friend": friend_name }, broadcast=True, include_self=False)

@socketio.on("logout")
def logout(username):
    db.set_status(username, 0)
    emit("update-logout", username, broadcast=True, include_self=False)

@socketio.on("login")
def login(username):
    db.set_status(username, 1)
    emit("update-login", username, broadcast=True, include_self=False)

@socketio.on("add_article")
def add_article(title, author, content):
    db.create_article(title, author, content)

@socketio.on("load_articles")
def load_articles():
    articles = db.get_all_articles()
    emit("load-articles", articles)

@socketio.on("update_articles")
def update_articles(title):
    article = db.get_article(title)
    emit("load-articles", article, broadcast=True, include_self=False)

@socketio.on("delete_article")
def delete_articles(article_title, article_id):
    db.delete_article(article_title)
    emit("update-delete-article", article_id, broadcast=True, include_self=False)

@socketio.on("modify_article")
def modify_article(article_title, modified_text):
    db.modify_article(article_title, modified_text)
    articles = db.get_all_articles()
    emit("reload-articles", articles, broadcast=True, include_self=False)

@socketio.on("append_comment")
def append_comment(article_title, comment, author):
    db.add_comment(article_title, comment, author)
    comments = db.retrieve_article_comment(article_title)
    emit("load-comments", comments, broadcast=True, include_self=False)

@socketio.on("retrieve_article_comment")
def retrieve_article_comment(article_title):
    comments = db.retrieve_article_comment(article_title)
    emit("load-comments", comments)

@socketio.on("delete_comment")
def delete_comment(comment_id, article_title):
    db.delete_comment(comment_id)
    comments = db.retrieve_article_comment(article_title)
    emit("load-comments", comments, broadcast=True, include_self=False)

@socketio.on("mute_user")
def mute_user(command, username):
    if command == "mute":
        db.mute_user(username, 1)
    elif command == "unmute":
        db.mute_user(username, 0)
    user_mute_status = {
        "command": command,
        "username": username
    }
    emit("update-user-muted", user_mute_status, broadcast=True, include_self=False)