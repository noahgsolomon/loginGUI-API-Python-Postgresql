import tkinter as tk
from tkinter import CENTER
import hashlib
import os
import uuid
import loginGUI
from API import cursor, conn

message = None
# Create the root window
root = tk.Tk()
root.geometry("600x400")
root.config(bg="#87CEEB")
root['cursor'] = 'arrow'
root.iconphoto(False, tk.PhotoImage(file='assets\\lock.png'))
root.title("Create Account")
root.resizable(False, False)

# Create the labels for the username and password
username_label = tk.Label(root, text="Username:", bg="#b1dff2", fg="#ffffff", font=('Bahnschrift', 15))
password_label = tk.Label(root, text="Password: ", bg="#b1dff2", fg="#ffffff", font=('Bahnschrift', 15))
username_label.place(relx=0.275, rely=0.4, anchor=CENTER)
password_label.place(relx=0.275, rely=0.5, anchor=CENTER)

# Create the entry fields for the username and password
username_entry = tk.Entry(root, font=("Bahnschrift", 15), width=15)
username_entry.place(relx=0.5, rely=0.4, anchor=CENTER)
password_entry = tk.Entry(root, font=("Bahnschrift", 15), width=15)
password_entry.place(relx=0.5, rely=0.5, anchor=CENTER)

# Create the login and create buttons
create_button = tk.Button(root, text="Create Account", padx=10, bg="#b1dff2", fg="#ffffff", font=('Bahnschrift', 12))
login = tk.Button(text='Login', borderwidth=0, font=('Bahnschrift', 10))
create_button.place(relx=0.5, rely=0.60, anchor=CENTER)
login.place(relx=0.5, rely=0.7, anchor=CENTER)


def create_account_enter(event):
    root.title("Create Account")
    login.config(borderwidth=0, font=('Bahnschrift', 10), fg='#000000', bg='#ffffff')
    login.place(relx=0.5, rely=0.7, anchor=CENTER)
    create_button.config(padx=10, bg="#b1dff2", fg="#ffffff", font=('Bahnschrift', 12), borderwidth=2)
    create_button.place(relx=0.5, rely=0.60, anchor=CENTER)
    create_button.bind('<Button-1>', create_account)
    login.bind("<Button-1>", login_account_enter)


def login_account_enter(event):
    root.title("Login")
    login.place(relx=0.5, rely=0.60, anchor=CENTER)
    login.config(padx=10, bg="#b1dff2", fg="#ffffff", font=('Bahnschrift', 12), borderwidth=2)
    create_button.config(borderwidth=0, font=('Bahnschrift', 8), fg='#000000', bg='#ffffff')
    create_button.place(relx=0.5, rely=0.7, anchor=CENTER)
    create_button.bind('<Button-1>', create_account_enter)
    login.bind("<Button-1>", login_account)


def login_account(event):
    global message
    username = username_entry.get()
    password = password_entry.get()
    cursor.execute("""SELECT salt, password, id FROM credentials WHERE username = '{}'""".format(username))
    details = cursor.fetchone()
    if details:
        # grabs stored random salt associates with username in database
        stored_salt = details['salt']
        # grabs stored string password in database that was attained from hashed_password
        stored_pass = details['password']
        id = details['id']
        # adding password sequence of bytes in utf-8 format to the salt bytes
        salted_password = password.encode('utf-8') + stored_salt
        # same thing as create_account. We did the same sequences with the same salt, so we should get the same password
        hashed_password = hashlib.sha256(salted_password).hexdigest()
        if stored_pass == str(hashed_password):
            if message:
                message.place_forget()

            message = tk.Label(root, text=f"Welcome, {username}", bg="#87CEEB", fg="#ffffff", font=('Bahnschrift', 10))
            message.place(relx=0.5, rely=0.8, anchor=CENTER)
            root.destroy()
            loginGUI.login(username, id)
        else:
            if message:
                message.place_forget()

            message = tk.Label(root, text=f"Invalid Credentials", bg="#87CEEB", fg="#A30000", font=('Bahnschrift', 10))
            message.place(relx=0.5, rely=0.8, anchor=CENTER)
    else:
        if message:
            message.place_forget()

        message = tk.Label(root, text=f"Invalid Username", bg="#87CEEB", fg="#A30000", font=('Bahnschrift', 10))
        message.place(relx=0.5, rely=0.8, anchor=CENTER)


def create_account(event):
    unique_id = str(uuid.uuid4())
    global message
    username = username_entry.get()
    password = password_entry.get()
    # creating random salt
    salt = os.urandom(16)
    # adding password sequence of bytes in utf-8 format to the salt bytes
    salted_password = password.encode('utf-8') + salt
    # calculates the SHA-256 hash of the salted_password bytes and returns it as a bytes object. Finally,
    # the hexdigest() method is called on the returned bytes object, which converts the hash to a string of hexadecimal digits
    hashed_password = hashlib.sha256(salted_password).hexdigest()
    cursor.execute("""SELECT * FROM credentials WHERE username = '{}'""".format(username))
    post = cursor.fetchone()
    if len(username) < 6 or len(password) < 6:
        if message:
            message.place_forget()
        else:
            message = None

        message = tk.Label(root, text="username and password \n must contain atleast 6 characters", bg="#87CEEB",
                           fg="#A30000", font=('Bahnschrift', 10))
        message.place(relx=0.5, rely=0.8, anchor=CENTER)

    elif not post:
        cursor.execute("""INSERT INTO credentials (id, username, password, salt) VALUES (%s, %s, %s, %s)""",
                       (unique_id, username, hashed_password, salt))
        conn.commit()
        username_entry.delete(0, 'end')
        password_entry.delete(0, 'end')

        if message:
            message.place_forget()
        else:
            message = None

        message = tk.Label(root, text="success!", bg="#87CEEB", fg="#00A300", font=('Bahnschrift', 15))
        message.place(relx=0.5, rely=0.8, anchor=CENTER)
        login_account_enter(event)
    else:
        if message:
            message.place_forget()
        else:
            message = None

        message = tk.Label(root, text="username is taken!", bg="#87CEEB", fg="#A30000", font=('Bahnschrift', 15))
        message.place(relx=0.5, rely=0.8, anchor=CENTER)


# hover cursor when over buttons
def on_cursor_over_button(event):
    event.widget['cursor'] = 'hand2'


create_button.bind('<Enter>', on_cursor_over_button)
login.bind('<Enter>', on_cursor_over_button)
login.bind("<Button-1>", login_account_enter)
create_button.bind('<Button-1>', create_account)
root.mainloop()
