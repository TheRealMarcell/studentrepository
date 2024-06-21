'''
db
database file, containing all the logic to interface with the sql database
'''

from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from models import Base, User, Friends, FriendshipStatus,EncryptedMessage,Articles,Comments
from sqlalchemy.exc import SQLAlchemyError
import json

from pathlib import Path

# creates the database directory
Path("database") \
    .mkdir(exist_ok=True)

# "database/main.db" specifies the database file
# change it if you wish
# turn echo = True to display the sql output
engine = create_engine("sqlite:///database/main.db", echo=False)

# initializes the database
Base.metadata.create_all(engine)

# inserts a user to the database
def insert_user(username: str, password: str, salt:str, role:str):
    with Session(engine) as session:
        user = User(username=username, password=password, salt=salt, role=role)
        session.add(user)
        session.commit()

# gets a user from the database
def get_user(username: str):
    with Session(engine) as session:
        return session.get(User, username)


def mute_user(username: str, status):
    with Session(engine) as session:
        user = session.get(User, username)
        user.muted = status
        session.commit()

def get_mute_status(username):
    with Session(engine) as session:
        user = session.get(User, username)
        return user.muted


def get_all_user():
    with Session(engine) as session:
        q = session.query(User)
        result = q.all()
        return result


def add_friend_request(sender_username: str, receiver_username: str):
    try:
        with Session(engine) as session:
            receiver = session.get(User, receiver_username)
            # print(receiver)
            if receiver:
                new_request = Friends(person1=sender_username, person2=receiver_username, status=FriendshipStatus.PENDING)
                session.add(new_request)
                session.commit()
                return True
            else:
                return False
    except SQLAlchemyError as e:
        print(f"Database error: {e}")  
        return False  


def get_received_friend_requests(username: str):
    with Session(engine) as session:
        return session.query(Friends).filter_by(person2=username, status=FriendshipStatus.PENDING).all()


def accept_friend_request(request_id: int):
    with Session(engine) as session:
        request = session.get(Friends, request_id)
        if request and request.status == FriendshipStatus.PENDING:
            request.status = FriendshipStatus.ACCEPTED
            session.commit()
            return True
        return False


def reject_friend_request(request_id: int):
    with Session(engine) as session:
        request = session.get(Friends, request_id)
        if request and request.status == FriendshipStatus.PENDING:
            request.status = FriendshipStatus.REJECTED
            session.commit()
            return True
        return False


def get_friends_list(username: str):
    with Session(engine) as session:
        friends = session.query(Friends).filter(
            ((Friends.person1 == username) | (Friends.person2 == username)),
            Friends.status == FriendshipStatus.ACCEPTED
        ).all()

        friend_usernames = []
        for friend in friends:
            if friend.person1 == username:
                friend_usernames.append(friend.person2)
            else:
                friend_usernames.append(friend.person1)

        return friend_usernames
    
def insert_encrypted_message(sender_username, receiver_username, encrypted_text, tag, salt):
    try:
        with Session(engine) as session:
            encrypted_message = EncryptedMessage(
                sender_username=sender_username,
                receiver_username=receiver_username,
                encrypted_text=encrypted_text,
                encryption_tag=tag,
                encryption_salt=salt
            )
            session.add(encrypted_message)
            session.commit()
            print("Encrypted message stored successfully.")
            return True
    except SQLAlchemyError as e:
        print(f"Failed to store encrypted message: {e}")
        return False


def get_encrypted_messages(username: str):
    with Session(engine) as session:
        # Retrieves messages sent by the user
        sent_messages = session.query(EncryptedMessage).filter_by(sender_username=username).all()
        # Retrieves messages received by the user
        received_messages = session.query(EncryptedMessage).filter_by(receiver_username=username).all()
        return sent_messages, received_messages

def get_role(username):
    with Session(engine) as session:
        user_data = session.get(User, username)
        role_raw = user_data.role
        print(type(role_raw))
        role = ""
        if role_raw == "1":
            role = "Student"
        elif role_raw == "2":
            role = "Academic"
        elif role_raw == "3":
            role = "Administrative Staff"
        elif role_raw == "4":
            role = "Admin"
        return role

def delete_friend(username, friend_name):
    try:
        with Session(engine) as session:
            query = session.query(Friends).filter(
            ((Friends.person1 == username) & (Friends.person2 == friend_name))
            | ((Friends.person1 == friend_name) & (Friends.person2 == username))
            ).one()
            session.delete(query)
            session.commit()
            return True
    except SQLAlchemyError as e:
        print(f"Failed to delete friend: {e}")
        return False

def get_status(username):
    with Session(engine) as session:
        user = session.get(User, username)
        status = user.online
        return status
    
def set_status(username: str, status: int):
    with Session(engine) as session:
        user = session.get(User, username)
        user.online = status
        session.commit()

def create_article(title: str, author:str, text:str):
    with Session(engine) as session:
        article = Articles(
                title=title,
                author=author,
                text=text
            )
        session.add(article)
        session.commit()

def get_article(article_title:str):
    with Session(engine) as session:
        print(article_title)
        article = session.query(Articles).filter_by(title=article_title).one()
        articles_list = []
        article_dict = {
                "title": article.title,
                "author": article.author,
                "text": article.text,
                "role": get_role(article.author)
            }
        articles_list.append(article_dict)
        return articles_list
    
def delete_article(article_title:str):
    with Session(engine) as session:
        article = session.query(Articles).filter_by(title=article_title).one()
        session.delete(article)
        session.commit()

def modify_article(article_title:str, new_text:str):
    with Session(engine) as session:
        article = session.query(Articles).filter_by(title=article_title).one()
        article.text = new_text
        session.commit()
            

def get_all_articles():
    with Session(engine) as session:
        articles = session.query(Articles).all()
        articles_list = []
        for article in articles:
            temp_dict = {
                "title": "",
                "author": "",
                "text": "",
                "role": ""
            }
            temp_dict["title"] = article.title 
            temp_dict["author"] = article.author
            temp_dict["text"] = article.text
            # user = session.get(User, article.author)
            temp_dict["role"] = get_role(article.author)

            articles_list.append(temp_dict)
        
        articles_as_json = json.dumps(articles_list)
        return articles_list
    
def get_article_by_id(id):
    with Session(engine) as session:
        article = session.get(Articles, id)
        article_content = {
            "title": article.title,
            "author": article.author,
            "text": article.text,
            "role": get_role(article.author)            
        }
        return article_content
    
def add_comment(article_title:str, comment:str, author:str):
    with Session(engine) as session:
        new_comment = Comments(
            article_title = article_title,
            comment = comment,
            author = author
        )
        session.add(new_comment)
        session.commit()

def retrieve_article_comment(input_article_title:str):
    with Session(engine) as session:
        article_comments = session.query(Comments).filter_by(article_title=input_article_title)
        comments = []
        
        for comment in article_comments:
            comment_content = {
                "comment": comment.comment,
                "author": comment.author,
                "role": get_role(comment.author)
            }
            comments.append(comment_content)
        return comments
    
def delete_comment(comment_content):
    with Session(engine) as session:
        comment = session.query(Comments).filter_by(comment=comment_content).one()
        session.delete(comment)
        session.commit()