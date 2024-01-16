# arguments used for socket connection:
#   host:   server ip address
#   port:   port used for socket connexion
#   action: authentification, check for new messages... Allows to identify the action to do at the server's side
#   user:   username
#   pwd:    password
#   arg1:   recipient of message or new password
#   arg2:   text of a new message
#   arg3:   currently not used 
#   Each message sent to the server contains different arguments separated by the following delimiter '::' .

import socket
import getpass #used for hiding the password while entering it in the terminal
import ssl

host = "10.0.0.1"
port = 65500  # The port used by the server for socket connection

ssl._create_default_https_context = ssl._create_unverified_context

def socketconnection(s_host,s_port, s_action, s_user,s_pwd, s_arg1,s_arg2,s_arg3):
    # At first, we will generate the massage to send
    s=s_action+'::'+s_user+'::'+s_pwd+'::'+s_arg1+'::'+s_arg2+'::'+s_arg3 # the string that will be sent to the server
    
    context=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.load_verify_locations('certs/ca-cert.pem')

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        try:
            ssl_client=context.wrap_socket(sock,server_hostname=s_host)
            ssl_client.connect((s_host,s_port))                               
                
        except: # in case if there's some problem with connection
            return "\nCouldn't connect. Verify that the server is online and try again\n\n"
       
        s=s.encode() # To be sent to the server, the sting must be encoded. In the server side, it should be decoded with .decode() tool
        ssl_client.sendall(s)
        data=''
        while data=='':
            data = ssl_client.recv(1024)
        data=data.decode()
        if s.decode().upper()=="EXIT":
            ssl_client.close()
    return data

    

def initiate_action(i_user,i_pwd):
    i_arg1=''
    i_arg2=''
    i_arg3=''
    print('\n(1) Check for news messages')
    print('(2) Send a new message')
    print('(3) View all incoming messages')
    print('(4) Change password')

    c=input('\nEnter the number of your choice: ')
    if c=='1':
        i_action='checkfornewmessages'
    if c=='2':
        i_action='newmessage'
        user_exists=0
        while user_exists==0:
            i_arg1=input('Who you want to send a message to? (username) : ')
            user_exists_result=socketconnection(host,port,'verityrecipient',i_user,i_pwd,i_arg1,i_arg2,i_arg3)
            if user_exists_result=='username exists':
                user_exists=1
            else:
                print(user_exists_result)
        i_arg2=input('Enter your message : ')
    if c=='3':
        i_action='showmessages'
    if c=='4':
        i_action='changepassword'
        i_arg1=getpass.getpass('Enter a new password: ')
        
        
    return socketconnection(host,port, i_action,i_user,i_pwd,i_arg1,i_arg2,i_arg3)


def authentification():
    # First of all we must check if our credentials are correct. Otherwise we can't move further.
    global user
    global pwd
    f_auth=0
    while f_auth==0:
        user=input('Enter your username: ')
        pwd=getpass.getpass('Enter your password: ')
        resp=socketconnection(host, port, 'auth',user,pwd,'','','')
        if resp=='ok':
            f_auth=1
            print ('\nAUTHENTIFICATION SUCCESSFUL\n')
        elif resp=='incorrect':
            print ('Incorrect credentials. Please, try again')
            
        else: # if there's a connection error
            print(resp)

        

user=''
pwd=''
authentification ()
while True:
    f_result=initiate_action(user,pwd)
    if f_result=='password has been changed':
        print('Log in with your new password')
        authentification()
    print(f_result)


