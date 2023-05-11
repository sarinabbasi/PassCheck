import requests # for making HTTP requests
import hashlib # for hashing passwords
from tkinter import * # for GUI
from PIL import ImageTk,Image # for image processing.


# Create a tkinter window and set its geometry,
# background color, and title. 
root = Tk()
root.geometry('600x500')
root.config(bg='#FFFFFF')
root.title('Password Checker')

#Load the background images and eye icons using PIL.
background = ImageTk.PhotoImage(Image.open("E:/Sarina/Coding/simple project/password cheker bg.jpg").resize((600,500)))
background2 = ImageTk.PhotoImage(Image.open("E:/Sarina/Coding/simple project/Background2.jpg").resize((600,500)))
eye_icon = ImageTk.PhotoImage(Image.open("E:/Sarina/Coding/simple project/eye_icon.jpg").resize((31,21)))
eye_close_icon = ImageTk.PhotoImage(Image.open("E:/Sarina/Coding/simple project/eye close icon.jpg").resize((31,21)))

bg = Label(image=background)
bg.pack()

# Define a function request_api_data(query_char)
# that takes the first 5 characters of the hashed password
# and sends a GET request to the Have I Been Pwned API to get all
# the hashes that match those first 5 characters. Returns the response object.

def request_api_data(query_char):
    url = 'https://api.pwnedpasswords.com/range/' + query_char
    res = requests.get(url)
    if res.status_code != 200:
        raise RuntimeError(f'Error fetching: {res.status_code}, check the api and try again ')
    return res

# Define a function get_password_leaks_counts(hashes, hash_to_check)
# that takes the response object and the tail (the rest of)
# the hashed password and returns the count of how many times the password appears in the API's data. 

def get_password_leaks_counts(hashes, hash_to_check):
    hashes = (line.split(':') for line in hashes.text.splitlines())
    for h, count in hashes:
        if h == hash_to_check:
            return count
    return 0      

# Define a function pwned_api_check(password)
# that takes the user's password and checks 
# if it has been pwned by calling the request_api_data()
# and get_password_leaks_counts() functions. 
# Returns the count of how many times the password has been pwned.

def pwned_api_check(password):
    sha1password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    first5_char, tail =sha1password[:5],sha1password[5:]
    response = request_api_data(first5_char)
   
    return get_password_leaks_counts(response, tail)

# Define a function main(args,m,info)
# that takes the user's password,
# sets the message for whether the password has been pwned or not,
# and displays the message in the GUI.

def main(args,m,info):
    count = pwned_api_check(args)
    if count:
        m.set(f'This password was\nfound {count} times\nyou should change\nyour password!')
        info.config(fg='#d60217')
        info.place(x=300,y=300)
    else:       
        m.set('Your password\nwas not found\ncarry on!')
        info.config(fg='#02d67e')
        info.place(x=300,y=310)
    return 'done'

# Define two functions show_pass() and hide_pass()
# that toggle the visibility of the password field when the user clicks on the eye icon.

def hide_pass(pwd,password):
    password.config(show='*')
    pwd.config(image=eye_icon,command= lambda : show_pass(pwd,password))

def show_pass(pwd,password):
    password.config(show='')
    pwd.config(image=eye_close_icon,command= lambda : hide_pass(pwd,password))

# Define a function cheak_the_password()
# that replaces the start screen with the password check screen when the user clicks on the Start button.

def cheak_the_password():
    start.destroy()
    title.destroy()
    des.destroy()
    bg.destroy()
    
    checked_pwd = StringVar()
    Label(image=background2).pack()

    Label(root,text='Enter your password',font=("Comic Sans MS",20),fg='#ed00aa',bg='#ffffff').place(x=95,y=90)
    password = Entry(root,show='*',font=("Comic Sans MS",15),width=24,fg='#000000',borderwidth=1,bg='#a1e1ff')
    password.place(x=85,y=150)
    
    Button(root,text='Check',font=('Comic Sans MS',13),fg='#ed00aa',borderwidth=1,bg='#FFFFFF',width=28,command=lambda: main(password.get(),checked_pwd,info)).place(x=87,y=200)
    state_pwd = Button(root,image=eye_icon,borderwidth=0,command=lambda:show_pass(state_pwd,password))
    state_pwd.place(x=340,y=155)
        
    info = Label(textvariable=checked_pwd,font=("Comic Sans MS",15),width=17,borderwidth=0,bg='#ffffff',justify='center')
    info.place(x=300,y=300)

# Create the start screen with a title, description, and a Start button that calls the cheak_the_password() function.


description = '''  Click start and secure your accounts with
our easy password checker. Get instant 
feedback and suggestions for improvements.
Stay safe with PassCheck.'''

###############################

title = Label(root,text='PassCheck',font=("Comic Sans MS",20),fg='#ed00aa',bg='#ffffff')
title.place(x=130,y=130)
des = Label(root,text=description,font=("Comic Sans MS",12),fg='#02a5f0',bg='#ffffff',justify='left')
des.place(x=130,y=180)
start = Button(root,text='Start',font=('Comic Sans MS',13),bg='#ffffff',fg='#ed00aa',width=10,borderwidth=1,command=cheak_the_password)
start.place(x=300,y=300)

###############################
root.mainloop()