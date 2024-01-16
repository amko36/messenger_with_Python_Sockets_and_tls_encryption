A messenger written in Python. 
For prerequisites, read PREREQUISITES.TXT.

Each user can send a message to another user, check for new messages, view all incoming messages and change his password.

USER AUTHENTIFICATION

All usernames and passwords are stored in passwd.txt. The passwords are hashed with md5 algorithm.
If you want to add a new user, you have to add a new line in passwd.txt. 
The format of the line is the following:
    username::hashed_password
The following command can be used for hashing in Python:
    hashlib.md5('your_password'.encode('utf-8')).hexdigest()
In current example, the usernames/passwords are the following:
    user1/hello1
    user2/hello2
    user3/hello3
Each user may change his password from the terminal.

MESSAGES

All incoming messages of each user are stored in {username}.txt file.
Unread messages are marked with 'u' letter, while 'r' letter is used to mark read messages.

POSSIBLE IMPROVEMENTS

This program can easily be improved by adding another useful feautures, such as deleting messages, showing conversations, downloading conversations, multiline messages, etc. 
