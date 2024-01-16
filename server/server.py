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
import hashlib # used for password hashing 
from datetime import datetime
import ssl

HOST = '0.0.0.0' 
PORT = 65500
authfile='passwd.txt' # this file contains a pair username:hashed password for each user

def readfile_splitlines(r_filename):
    try:
        f=open(r_filename, 'r')
        r_result=f.read().splitlines()
        f.close()
        
    except:
        r_result=['READING ERROR']
    return r_result

def write_lines_to_file(w_filename,w_list):
    # write a list to a file. Each element of the list should be a separated line (just adding \n at the end of each element)
    f = open(w_filename, 'w')
    for i in range(len(w_list)):
        f.write(w_list[i]+'\n')
    f.close()

def append_new_line_to_file(a_filename,a_str):
    f = open(a_filename, 'a')
    f.write(a_str+'\n')
    f.close()

def replace_textline_in_list(r_list, r_text,r_ntext): # r_text - old string ; r-ntext - new one
    for i in range(len(r_list)):
        if r_list[i]==r_text:
            r_list[i]=r_ntext
            break
    return r_list


def decompose (d_data):
    # This funtion is used to decompose the received string into a list of arguments
    # For example, the string 'auth::user::password:' will be decomposed like this ['auth', 'user','password']
    d_datalist=[]
    d_str=''
    if len(d_data)>0:
        
        d_str=d_data[0] # each agrument will first be extracted in this variable and then it will be added into the d_datalist list.
        # we can directly extract the first character, as it will never be a delimiter character, as well as the last one  

        d_delimiter=0 # indicates whether the '::' delimiter is found (if equals 1) or not (if equals 0)
        
        for i in range(1,len(d_data)-1):
            if (d_data[i]==':' and d_data[i+1]==':') or (d_data[i]==':' and d_data[i-1]==':'):
                d_delimiter=1 #delimiter detected

            if d_delimiter==0: 
                d_str=d_str+d_data[i]
            elif d_data[i]!=':': # this case will be met just after the delimiter
                d_str=d_str+d_data[i]
                d_delimiter=0
                
            if d_delimiter==1 and len(d_str)>0: # adding a new extracted word to the list
                d_datalist=d_datalist+[d_str]
                d_str=''
                d_delimiter=0

        d_str=d_str+d_data[len(d_data)-1] # completing the last extracted element with the last character

    d_datalist=d_datalist+[d_str,'','','','','',''] # blanc cases are added just in case if there isn't enough arguments to call other functions
    return d_datalist        


def action_authentification(a_user,a_pwd): # checks if there's a string {a_user}::{hassh of a_pwd} in the authentification file
    auth_list=readfile_splitlines(authfile)

    a_str=a_user+'::'+hashlib.md5(a_pwd.encode('utf-8')).hexdigest() 

    if a_str in auth_list: # verifies if the hash of a_pwd matches one of the string user:hashed_password in authentification file
        return 'ok'
    else:
        return 'incorrect'



def action_change_password(c_user,c_pwd, c_npwd): # searches the line {c_user}:{hash of c_pwd} and remplaces it with {c_user}:{hash of c_npwd}

    auth_list=readfile_splitlines(authfile)

    c_str=c_user+'::'+hashlib.md5(c_pwd.encode('utf-8')).hexdigest() # line to be replaced
    c_nstr=c_user+'::'+hashlib.md5(c_npwd.encode('utf-8')).hexdigest() # replacing line
    n_auth_list=replace_textline_in_list(auth_list, c_str,c_nstr)

    write_lines_to_file(authfile,n_auth_list)

    return 'password has been changed'


def action_new_message(a_user,a_arg1, a_arg2): 
    a_now=datetime.now().strftime("%d/%m/%Y %H:%M:%S") # date and time
    a_newstring='u::'+a_user+'::'+a_now+'::'+a_arg2+''
    append_new_line_to_file(a_arg1+'.txt',a_newstring)
    return 'Message sent'

def action_verify_recipient(a_user): # verifies if the username exists in authfile
    user_exists=0
    auth_list=readfile_splitlines(authfile)
    for i in range(len(auth_list)):
        a_extracted_user=decompose(auth_list[i])[0]
        print(a_user,':',a_extracted_user)
        if a_user==a_extracted_user:
            user_exists=1
    if user_exists==1:
        return 'username exists'
    else:
        return "\nThe username you entered doesn't exist. Please, try again.\n\n"
        

def action_check_for_new_messages(c_user):
        c_file=c_user+'.txt' # all messages are stored in user's text file
        c_mess=[] # this variable is used to decompose each message :state of the message:sender:date and time:message: and write it into a list
        c_mts='' # messages to show
        c_markasread=[] # this list will contain the numbers of lines with messages that should be marked as read
        messages_list=readfile_splitlines(c_file)
        # Each textline is similar to the next:
        # :state of the message:sender:date and time:message
        # state of the message is either 'r'(read) or 'u' (unread)
        f = open(c_file, "w")
        
        for i in range(len(messages_list)):
            c_mess=decompose(messages_list[i])
            if c_mess[0]=='u':
                messages_list[i]=messages_list[i].replace('u::','r::') # mark the mesage as read
                
                c_mts=c_mts+'\n\n   FROM: '+ c_mess[1]+'\n   Date and time:'+c_mess[2]+'\n     '+c_mess[3]+'\n\n'
                        
            f.write(messages_list[i]+'\n')# we rewrite each string to the file in order to have the right state of mesage
        
        f.close()
            
        return c_mts

def action_show_messages(c_user):
        c_file=c_user+'.txt' # all messages are stored in user's text file
        c_mess=[] # this variable is used to decompose each string like 'state of the message::sender::date and time::message' and to write it into a list
        c_mts='' # generated message to show
        messages_list=readfile_splitlines(c_file)
        # Each textline is similar to the next:
        # :state of the message:sender:date and time:message
        # state of the message is either 'r'(read) or 'u' (unread)

        for i in range(len(messages_list)):
            c_mess=decompose(messages_list[i])
            c_mts=c_mts+'\n\n   FROM: '+ c_mess[1]+'\n   Date and time:'+c_mess[2]+'\n     '+c_mess[3]+'\n\n'
        print(c_mts)
        return c_mts




def handle(h_action, h_user, h_pwd, h_arg1, h_arg2, h_arg3):
    # h_arg1: new password
    if h_action=='auth':
        return 'ok' #the authentification has been done before calling to this funtion, so it's ok

    if h_action=='checkfornewmessages':
        return action_check_for_new_messages(h_user)

    if h_action=='changepassword':
        return action_change_password(h_user,h_pwd, h_arg1)

    if h_action=='newmessage':
        return action_new_message(h_user,h_arg1, h_arg2)

    if h_action=='showmessages':
        s=action_show_messages(h_user)
        return s
        print (s)    

    if h_action=='verityrecipient':
        s=action_verify_recipient(h_arg1)
        return s
        print (s)            




def create_socket():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:

        context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain('certs/cert-server.pem','certs/cert-key.pem')
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1) #  Allows to avoid an error when port is blocked by another process.
        sock.bind((HOST, PORT))
        sock.listen()
        print("waiting for incoming connexions")

        #securing the socket
        srv_ssl=context.wrap_socket(sock, server_side=True)
        try:
            conn, addr = srv_ssl.accept()
            print(f"Connected with {addr}")
            data = conn.recv(1024) 
            data=data.decode()
            datalist= decompose(data)
            # After decomposition the order of the arguments in the list will be the following:
            # [action, user, password, arg1, arg2, arg3]
            s_action=datalist[0]
            s_user=datalist[1]
            s_pwd=datalist[2]
            s_arg1=datalist[3]
            s_arg2=datalist[4]
            s_arg3=datalist[5]
            if action_authentification(s_user,s_pwd)=='ok':
                message=handle(s_action, s_user, s_pwd, s_arg1, s_arg2,s_arg3)
                
            else:
                print('Incorrect user or password')
                message='incorrect'
                
            # print(f"Data received: {datalist}") #you can uncomment this line if you want to see all the data that arrives to the server.
            message=message.encode()
            conn.sendall(message)
            conn.close()
        except:
            sock.close()
            return "Couldn't connect to the server"
        
    sock.close()
    return 'ok'


while True:
    ss=create_socket()
    print (ss)


            
