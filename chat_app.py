import sqlite3
import sys
import re
import hashlib
from cryptography.fernet import Fernet
import secrets
from datetime import datetime

# Initialize SQLite3 database
conn = sqlite3.connect('chat.db')
c = conn.cursor()

# Create users table if not exists
c.execute('''CREATE TABLE IF NOT EXISTS users (
             id INTEGER PRIMARY KEY,
             username TEXT NOT NULL UNIQUE,
             password_hash TEXT NOT NULL,
             salt TEXT NOT NULL,
             encryption_key BLOB NOT NULL
             )''')

# Create messages table if not exists with timestamp
c.execute('''CREATE TABLE IF NOT EXISTS messages (
             id INTEGER PRIMARY KEY,
             sender_id INTEGER NOT NULL,
             receiver_id INTEGER NOT NULL,
             message BLOB NOT NULL,
             timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
             FOREIGN KEY (sender_id) REFERENCES users(id),
             FOREIGN KEY (receiver_id) REFERENCES users(id)
             )''')

# Create group chats table if not exists
c.execute('''CREATE TABLE IF NOT EXISTS group_chats (
             id INTEGER PRIMARY KEY,
             group_name TEXT NOT NULL UNIQUE
             )''')

# Create group chat users table if not exists
c.execute('''CREATE TABLE IF NOT EXISTS group_chat_users (
             id INTEGER PRIMARY KEY,
             group_chat_id INTEGER NOT NULL,
             user_id INTEGER NOT NULL,
             FOREIGN KEY (group_chat_id) REFERENCES group_chats(id),
             FOREIGN KEY (user_id) REFERENCES users(id)
             )''')

# Create group chat permissions table if not exists
c.execute('''CREATE TABLE IF NOT EXISTS group_chat_permissions (
             id INTEGER PRIMARY KEY,
             group_chat_id INTEGER NOT NULL,
             user_id INTEGER NOT NULL,
             permission_level TEXT NOT NULL,
             FOREIGN KEY (group_chat_id) REFERENCES group_chats(id),
             FOREIGN KEY (user_id) REFERENCES users(id)
             )''')

conn.commit()

# Generate a key for encryption
def generate_key():
    return Fernet.generate_key()

# Encrypt a message using a key
def encrypt_message(message, key):
    cipher_suite = Fernet(key)
    return cipher_suite.encrypt(message.encode())

# Decrypt a message using a key
def decrypt_message(encrypted_message, key):
    cipher_suite = Fernet(key)
    return cipher_suite.decrypt(encrypted_message).decode()

# Function to validate username with advanced regular expression
def validate_username(username):
    if re.match(r'^[a-zA-Z0-9_]+$', username):
        return True
    else:
        print("Invalid username. Usernames can only contain letters, numbers, and underscores.")
        return False

# Function to validate password with advanced regular expression
def validate_password(password):
    if re.match(r'^(?=.*\d)(?=.*[a-z])(?=.*[A-Z])(?=.*[!@#$%^&*()_+}{":;\'?/>.<,])(?=.*[a-zA-Z]).{8,}$', password):
        return True
    else:
        print("Invalid password. Passwords must contain at least 8 characters, including at least one uppercase letter, one lowercase letter, one digit, and one special character.")
        return False

# Encrypt a password and return the hash and salt
def encrypt_password(password):
    salt = secrets.token_hex(16)
    hashed_password = hashlib.sha256((password + salt).encode()).hexdigest()
    return hashed_password, salt

# Decrypt a password using the provided key
def decrypt_password(encrypted_password, key):
    cipher_suite = Fernet(key)
    return cipher_suite.decrypt(encrypted_password).decode()

# Function to register user
def register_user(username, password):
    try:
        if validate_username(username) and validate_password(password):
            password_hash, salt = encrypt_password(password)
            key = generate_key()  # Generate encryption key for the user
            encrypted_key = encrypt_message(key.decode(), password_hash.encode())  # Encrypt key with user's password hash
            c.execute("INSERT INTO users (username, password_hash, salt, encryption_key) VALUES (?, ?, ?, ?)", (username, password_hash, salt, encrypted_key))
            conn.commit()
            print("User registered successfully!")
    except sqlite3.IntegrityError:
        print("Username already exists. Please choose a different username.")
    except Exception as e:
        print("Error:", e)

# Function to login user and retrieve encryption key
def login_user(username, password):
    try:
        c.execute("SELECT id, password_hash, salt, encryption_key FROM users WHERE username=?", (username,))
        user = c.fetchone()
        if user:
            user_id, stored_password_hash, salt, encrypted_key = user
            hashed_password = hashlib.sha256((password + salt).encode()).hexdigest()
            if hashed_password == stored_password_hash:
                key = decrypt_message(encrypted_key, hashed_password.encode())  # Decrypt user's encryption key
                print("Login successful!")
                return user_id, key
            else:
                print("Invalid username or password.")
                return None, None
        else:
            print("Invalid username or password.")
            return None, None
    except Exception as e:
        print("Error:", e)
        return None, None

# Function to handle user joining the chat
def join_chat(username):
    try:
        c.execute("INSERT INTO users (username) VALUES (?)", (username,))
        conn.commit()
        print(f"Welcome to the chat, {username}!")
    except Exception as e:
        print("Error:", e)

# Function to handle user leaving the chat
def leave_chat(username):
    try:
        c.execute("DELETE FROM users WHERE username=?", (username,))
        conn.commit()
        print(f"Goodbye, {username}!")
    except Exception as e:
        print("Error:", e)

# Function to send a message to a specific user
def send_message(sender_id, receiver_username, message, key):
    try:
        c.execute("SELECT id FROM users WHERE username=?", (receiver_username,))
        receiver = c.fetchone()
        if receiver:
            receiver_id = receiver[0]
            encrypted_message = encrypt_message(message, key)
            c.execute("INSERT INTO messages (sender_id, receiver_id, message, timestamp) VALUES (?, ?, ?, ?)", (sender_id, receiver_id, encrypted_message, datetime.now()))
            conn.commit()
            print(f"Message sent to {receiver_username}.")
        else:
            print(f"User {receiver_username} not found.")
    except Exception as e:
        print("Error:", e)

# Function to send a message to all users
def send_message_to_all(sender_id, message, key):
    try:
        c.execute("SELECT id FROM users WHERE id!=?", (sender_id,))
        receivers = c.fetchall()
        for receiver_id in receivers:
            encrypted_message = encrypt_message(message, key)
            c.execute("INSERT INTO messages (sender_id, receiver_id, message, timestamp) VALUES (?, ?, ?, ?)", (sender_id, receiver_id[0], encrypted_message, datetime.now()))
        conn.commit()
        print("Message sent to all users.")
    except Exception as e:
        print("Error:", e)

# Function to send a message to a group chat
def send_message_to_group_chat(sender_id, group_chat_id, message, key):
    try:
        # Retrieve all members of the group chat
        c.execute("SELECT user_id FROM group_chat_permissions WHERE group_chat_id=? AND permission_level='member'", (group_chat_id,))
        receivers = c.fetchall()
        # Send the message to each member of the group chat
        for receiver in receivers:
            encrypted_message = encrypt_message(message, key)
            c.execute("INSERT INTO messages (sender_id, receiver_id, message, timestamp) VALUES (?, ?, ?, ?)", (sender_id, receiver[0], encrypted_message, datetime.now()))
        conn.commit()
        print("Message sent to group chat.")
    except Exception as e:
        print("Error:", e)

# Function to display all users in the chat
def display_users():
    try:
        c.execute("SELECT * FROM users")
        users = c.fetchall()
        print("Users currently in the chat:")
        for user in users:
            print(user[1])
    except Exception as e:
        print("Error:", e)

# Function to retrieve and display messages for a specific user
def display_messages(username, key):
    try:
        c.execute("SELECT m.timestamp, u.username, m.message FROM messages m JOIN users u ON m.sender_id=u.id WHERE m.receiver_id = (SELECT id FROM users WHERE username=?) ORDER BY m.timestamp", (username,))
        messages = c.fetchall()
        for message in messages:
            decrypted_message = decrypt_message(message[2], key)
            print(f"{message[0]} - {message[1]}: {decrypted_message}")
    except Exception as e:
        print("Error:", e)

# Function to show old messages between two specific users
def show_old_messages(user1, user2, key):
    try:
        c.execute("SELECT m.timestamp, u1.username AS sender, u2.username AS receiver, m.message FROM messages m JOIN users u1 ON m.sender_id=u1.id JOIN users u2 ON m.receiver_id=u2.id WHERE ((u1.username=? AND u2.username=?) OR (u1.username=? AND u2.username=?)) ORDER BY m.timestamp", (user1, user2, user2, user1))
        messages = c.fetchall()
        for message in messages:
            decrypted_message = decrypt_message(message[3], key)
            print(f"{message[0]} - {message[1]} to {message[2]}: {decrypted_message}")
    except Exception as e:
        print("Error:", e)

# Function to show received messages for a specific user
def show_received_messages(current_user_id, key):
    try:
        c.execute("SELECT m.timestamp, u.username, m.message FROM messages m JOIN users u ON m.sender_id=u.id WHERE m.receiver_id=? ORDER BY m.timestamp", (current_user_id,))
        messages = c.fetchall()
        for message in messages:
            decrypted_message = decrypt_message(message[2], key)
            print(f"{message[0]} - {message[1]}: {decrypted_message}")
    except Exception as e:
        print("Error:", e)

# Main function
def main():
    if len(sys.argv) < 2:
        print("Usage: python script.py <command> [options]")
        sys.exit(1)
    
    command = sys.argv[1]
    
    if command == 'register':
        if len(sys.argv) != 4:
            print("Usage: python script.py register <username> <password>")
            sys.exit(1)
        username = sys.argv[2]
        password = sys.argv[3]
        register_user(username, password)
    
    elif command == 'login':
        if len(sys.argv) != 4:
            print("Usage: python script.py login <username> <password>")
            sys.exit(1)
        username = sys.argv[2]
        password = sys.argv[3]
        user_id, key = login_user(username, password)
        if key:
            while True:
                action = input("Enter action (join, leave, send, show, display, old, received, exit): ").strip()
                if action == 'join':
                    username_to_join = input("Enter username to join: ").strip()
                    join_chat(username_to_join)
                elif action == 'leave':
                    username_to_leave = input("Enter username to leave: ").strip()
                    leave_chat(username_to_leave)
                elif action == 'send':
                    receiver_username = input("Enter recipient username: ").strip()
                    message = input("Enter message: ").strip()
                    send_message(user_id, receiver_username, message, key)
                elif action == 'send_all':
                    message = input("Enter message: ").strip()
                    send_message_to_all(user_id, message, key)
                elif action == 'send_group':
                    group_chat_id = int(input("Enter group chat ID: ").strip())
                    message = input("Enter message: ").strip()
                    send_message_to_group_chat(user_id, group_chat_id, message, key)
                elif action == 'show':
                    display_messages(username, key)
                elif action == 'display':
                    display_users()
                elif action == 'old':
                    user2 = input("Enter the second user's username: ").strip()
                    show_old_messages(username, user2, key)
                elif action == 'received':
                    show_received_messages(user_id, key)
                elif action == 'exit':
                    print("Exiting...")
                    break
                else:
                    print("Unknown action. Please try again.")
    
    else:
        print("Unknown command. Please use 'register' or 'login'.")
        sys.exit(1)

if __name__ == "__main__":
    main()
