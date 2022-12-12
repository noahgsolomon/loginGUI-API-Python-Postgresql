import hashlib
import tkinter as tk
from tkinter.constants import CENTER

from PIL import Image

from API import cursor, conn


def login(username, id):
    root = tk.Tk()
    root.geometry("800x400")
    root.config(bg="#ffffff")
    root['cursor'] = 'arrow'
    root.iconphoto(False, tk.PhotoImage(file='assets\\user.png'))
    root.title("")

    welcome = tk.Label(text=f"Welcome, {username},\n what would you like to do?", font=('Bahnschrift', 15),
                       bg='#ffffff')
    welcome.place(relx=0.5, rely=0.2, anchor=CENTER)

    change_user = tk.Button(root, text="Change Username", padx=10, font=('Bahnschrift', 12))
    change_user.place(relx=0.5, rely=0.5, anchor=CENTER)
    change_pass = tk.Button(root, text="Change Password", padx=10, font=('Bahnschrift', 12))
    change_pass.place(relx=0.5, rely=0.6, anchor=CENTER)
    change_theme = tk.Button(root, text="Change Theme", padx=10, font=('Bahnschrift', 12))
    change_theme.place(relx=0.5, rely=0.7, anchor=CENTER)

    def change_user_enter(event):
        message = None
        change_user.destroy()
        change_pass.destroy()
        change_theme.destroy()
        welcome.destroy()
        response = tk.Label(text=f"What would you like to change your username to?",
                            font=('Bahnschrift', 15),
                            bg='#ffffff')
        response.place(relx=0.5, rely=0.2, anchor=CENTER)
        username_label = tk.Label(root, text="replace username:", font=('Bahnschrift', 15))
        username_label.place(relx=0.275, rely=0.4, anchor=CENTER)
        username_entry = tk.Entry(root, font=("Bahnschrift", 15), width=15, borderwidth=3)
        username_entry.place(relx=0.5, rely=0.4, anchor=CENTER)
        enter = tk.Button(text="Enter", font=('Bahnschrift', 11),
                          bg='#ffffff', padx=15)
        enter.place(relx=0.65, rely=0.4, anchor=CENTER)

        def submit_user(event):
            nonlocal message
            nonlocal response
            new_user = username_entry.get()
            cursor.execute("""SELECT username FROM credentials WHERE id = '{}'""".format(id))
            curr_user = cursor.fetchone()
            curr_username = curr_user.get("username")
            cursor.execute("""SELECT username FROM credentials WHERE username = '{}'""".format(new_user))
            user_present = cursor.fetchone()
            print(user_present)

            if len(new_user) < 6:
                if message:
                    message.place_forget()
                else:
                    message = None

                message = tk.Label(root, text="username must be at least 6 characters", fg="#A30000", bg="#ffffff",
                                   font=('Bahnschrift', 15))
                message.place(relx=0.5, rely=0.7, anchor=CENTER)
            elif user_present:
                print("hello")
                if message:
                    message.place_forget()
                else:
                    message = None

                message = tk.Label(root, text="username already exists", fg="#A30000", bg="#ffffff",
                                   font=('Bahnschrift', 15))
                message.place(relx=0.5, rely=0.7, anchor=CENTER)
            else:
                cursor.execute(
                    """UPDATE credentials SET username = '{}' WHERE username = '{}'""".format(new_user, curr_username))
                conn.commit()

                if message:
                    message.place_forget()
                else:
                    message = None

                message = tk.Label(root, text="successfully changed!", fg="#00A300", bg="#ffffff",
                                   font=('Bahnschrift', 15))
                message.place(relx=0.5, rely=0.7, anchor=CENTER)
        enter.bind('<Enter>', on_cursor_over_button)
        enter.bind("<Button-1>", submit_user)

    def change_pass_enter(event):
        message = None
        change_user.destroy()
        change_pass.destroy()
        change_theme.destroy()
        welcome.destroy()
        response = tk.Label(text=f"What would you like to change your password to?",
                            font=('Bahnschrift', 15),
                            bg='#ffffff')
        response.place(relx=0.5, rely=0.2, anchor=CENTER)
        password_label = tk.Label(root, text="replace password:", font=('Bahnschrift', 15))
        password_label.place(relx=0.275, rely=0.4, anchor=CENTER)
        password_entry = tk.Entry(root, font=("Bahnschrift", 15), width=15, borderwidth=3)
        password_entry.place(relx=0.5, rely=0.4, anchor=CENTER)
        enter = tk.Button(text="Enter", font=('Bahnschrift', 11),
                          bg='#ffffff', padx=15)
        enter.place(relx=0.65, rely=0.4, anchor=CENTER)

        def submit_pass(event):
            nonlocal message
            new_pass = password_entry.get()
            if len(new_pass) < 6:
                if message:
                    message.place_forget()
                else:
                    message = None

                message = tk.Label(root, text="password must be at least 6 characters", fg="#A30000", bg="#ffffff",
                                   font=('Bahnschrift', 15))
                message.place(relx=0.5, rely=0.7, anchor=CENTER)
            else:

                cursor.execute("""SELECT salt, password, username FROM credentials WHERE id = '{}'""".format(id))
                details = cursor.fetchone()
                stored_salt = details['salt']
                stored_user = details['username']
                stored_pass = details['password']
                new_salted_password = new_pass.encode('utf-8') + stored_salt
                new_hashed_password = hashlib.sha256(new_salted_password).hexdigest()
                if new_hashed_password == stored_pass:
                    if message:
                        message.place_forget()
                    else:
                        message = None

                    message = tk.Label(root, text="cannot change password to current password", fg="#A30000", bg="#ffffff",
                                       font=('Bahnschrift', 15))
                    message.place(relx=0.5, rely=0.7, anchor=CENTER)
                else:
                    cursor.execute("""UPDATE credentials SET password = %s WHERE username = %s""",
                                   (new_hashed_password, stored_user))
                    conn.commit()

                    if message:
                        message.place_forget()
                    else:
                        message = None

                    message = tk.Label(root, text="successfully changed password!", fg="#00A300", bg="#ffffff",
                                       font=('Bahnschrift', 15))
                    message.place(relx=0.5, rely=0.7, anchor=CENTER)

        enter.bind('<Enter>', on_cursor_over_button)
        enter.bind("<Button-1>", submit_pass)

    def on_cursor_over_button(event):
        event.widget['cursor'] = 'hand2'

    change_user.bind("<Button-1>", change_user_enter)
    change_pass.bind("<Button-1>", change_pass_enter)
    change_theme.bind("<Button-1>", change_user_enter)
    change_user.bind('<Enter>', on_cursor_over_button)
    change_pass.bind('<Enter>', on_cursor_over_button)
    change_theme.bind('<Enter>', on_cursor_over_button)
