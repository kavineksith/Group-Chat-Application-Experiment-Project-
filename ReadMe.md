## Chat Application Documentation

## Overview

This Python script is designed to facilitate a secure and feature-rich chat application using SQLite for database management and `cryptography` for encryption. The script allows users to register, login, and perform various chat operations, including sending messages to individual users, broadcasting messages to all users, and managing group chats. It includes robust security measures with encryption for user credentials and messages, ensuring that user data remains confidential.

## Features

- **User Management**: Register and login users with encrypted passwords.
- **Message Handling**: Send and receive messages between users and within group chats.
- **Group Chat Functionality**: Create and manage group chats with permissions.
- **Encryption**: Secure user passwords and messages using AES encryption.
- **Timestamping**: Track message timestamps to maintain the sequence of communications.
- **User Interface**: Command-line interface for interacting with the application.

## Dependencies

The script relies on the following Python modules:

- **`sqlite3`**: For interacting with the SQLite database.
- **`sys`**: For command-line argument parsing.
- **`re`**: For regular expression-based input validation.
- **`hashlib`**: For hashing passwords.
- **`cryptography`**: For message and key encryption.
- **`secrets`**: For generating secure salts.
- **`datetime`**: For managing timestamps.

To install the necessary dependencies, you can use the following command:

```sh
pip install cryptography
```

The `sqlite3` module is included with Python’s standard library, so no additional installation is required for it.

## Usage

The script is executed from the command line with different commands to perform various actions. Below are the instructions for using the script:

1. **Register a New User**:

   ```sh
   python chat_app.py register <username> <password>
   ```

   - `username`: The desired username.
   - `password`: The chosen password (must meet security criteria).

2. **Login a User**:

   ```sh
   python chat_app.py login <username> <password>
   ```

   - `username`: The username for login.
   - `password`: The password associated with the username.

## Interactive Commands

Once logged in, users can interact with the application through a command-line interface. The available interactive commands are:

- **`join`**: Join a new user to the chat.
  ```sh
  Enter username to join: <username>
  ```

- **`leave`**: Remove a user from the chat.
  ```sh
  Enter username to leave: <username>
  ```

- **`send`**: Send a message to a specific user.
  ```sh
  Enter recipient username: <username>
  Enter message: <message>
  ```

- **`send_all`**: Send a message to all users.
  ```sh
  Enter message: <message>
  ```

- **`send_group`**: Send a message to a group chat.
  ```sh
  Enter group chat ID: <group_chat_id>
  Enter message: <message>
  ```

- **`show`**: Display all messages received by the logged-in user.
  
- **`display`**: Show all users currently in the chat.
  
- **`old`**: Show old messages between two specific users.
  ```sh
  Enter the second user's username: <username>
  ```

- **`received`**: Show all received messages for the logged-in user.

- **`exit`**: Exit the application.

## Special Commands

In addition to the interactive commands, the script handles the following special operations:

- **User Registration**: This command creates a new user with encrypted credentials. If a username is already taken, an error message will be displayed.
  
- **User Login**: This command authenticates the user and provides access to the chat features if the credentials are valid.

- **Message Encryption/Decryption**: Messages are encrypted using AES encryption before storage and decrypted when displayed, ensuring data privacy.

## Conclusion

This Python script provides a robust framework for a chat application, integrating user authentication, message handling, and group chat management with strong security features. The use of encryption ensures that user data remains confidential, while the timestamping functionality helps maintain the chronological order of messages. By following the provided usage instructions and commands, users can effectively interact with the application, manage their communications, and engage in secure, encrypted conversations.

For any issues or further customization, users are encouraged to review the script’s source code or seek additional guidance from the development community.

## **License**
This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

### **Disclaimer:**
Kindly note that this project is developed solely for educational purposes, not intended for industrial use, as its sole intention lies within the realm of education. We emphatically underscore that this endeavor is not sanctioned for industrial application. It is imperative to bear in mind that any utilization of this project for commercial endeavors falls outside the intended scope and responsibility of its creators. Thus, we explicitly disclaim any liability or accountability for such usage.
