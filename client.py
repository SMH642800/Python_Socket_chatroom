# -*- coding: utf8 -*-

# from socket import *
from tkinter import *
import tkinter as tk
import threading
import hashlib
import socket
import struct
import time
import sys
import os

from tkinter import filedialog
from tkinter import messagebox
from PIL import ImageTk, Image


import encryption

# ========================================== Default attribute configure ===============================================

login_window = None
main_window = None
client_socket = None
udp_socket = None
current_connect_session = ''
username = ''
users = {}
filename = ''
filename_short = ''
file_transfer_waiting = False

HOST = "127.111.0.1"
PORT = 12345

MCAST_GRP = '224.111.1.1'
MCAST_PORT = 5007

# ========================================= Tkinter Login and Main windows =============================================


class LoginWin:
    def __init__(self):
        self.window = tk.Tk()

        self.username = tk.StringVar()
        self.password = tk.StringVar()

        # Adjust window size
        self.window.title("Chat Login")
        self.window.geometry('320x190')
        self.window.resizable(width=False, height=False)

        # Add image file
        self.bg = ImageTk.PhotoImage(Image.open('picture/IMG_7753.jpg'))

        # Create a Canvas
        self.img_canvas = Canvas(self.window)
        self.img_canvas.pack(fill='both', expand=True)

        # Display image
        self.img_canvas.create_image(0, 0, image=self.bg)
        # self.img_canvas.create_image(0, 0, image=self.bg, anchor='nw')

        # Display login context: Account
        self.label1 = tk.Label(self.window)
        self.label1.place(relx=0.12, rely=0.18, height=22, width=40)
        self.label1.configure(text='帳號', font=("Arial", 12), bg='light slate gray')

        # Input the account information
        self.entry_username = tk.Entry(self.window)
        self.entry_username.place(relx=0.28, rely=0.18, height=22, relwidth=0.6)
        self.entry_username.configure(textvariable=self.username)

        # Display login context: Password
        self.label2 = tk.Label(self.window)
        self.label2.place(relx=0.12, rely=0.35, height=22, width=40)
        self.label2.configure(text='密碼', font=("Arial", 12), bg='light slate gray')

        # Input the password information
        self.entry_password = tk.Entry(self.window)
        self.entry_password.place(relx=0.28, rely=0.35, height=22, relwidth=0.6)
        self.entry_password.configure(show='*', textvariable=self.password)

        # Display Login and register button
        self.button_login = tk.Button(self.window)
        self.button_login.place(relx=0.2, rely=0.65, height=28, width=70)
        self.button_login.configure(text='Login', font=("Arial", 12), bg='light slate gray')
        self.button_register = tk.Button(self.window)
        self.button_register.place(relx=0.6, rely=0.65, height=28, width=70)
        self.button_register.configure(text='Register', font=("Arial", 12), bg='light slate gray')

    # show the login window
    def show(self):
        self.window.mainloop()

    # not show the login window
    def destroy(self):
        self.window.destroy()


class MainWin:

    turn_off = None

    def __init__(self):
        self.window = tk.Tk()
        self.window.protocol('WM_DELETE_WINDOW', self.on_closing)

        # Adjust window size
        self.window.title("Chat Room")
        self.window.geometry('500x350')
        self.window.resizable(width=False, height=False)

        # Add image file
        self.bg = ImageTk.PhotoImage(Image.open('picture/IMG_6158.jpg'))

        # Create a Canvas
        self.img_canvas = Canvas(self.window)
        self.img_canvas.pack(fill='both', expand=True)

        # Display image
        self.img_canvas.create_image(0, 0, image=self.bg)
        # self.img_canvas.create_image(0, 0, image=self.bg, anchor='nw')

        # username and message display format
        self.message = tk.StringVar()
        self.username = tk.StringVar()

        # display this client username at the top and center
        self.label1 = tk.Label(self.window)
        self.label1.place(relx=0.3, rely=0.07, height=25, width=100)
        self.label1.configure(textvariable=self.username, font=("Arial", 12), bg='light slate gray')

        # display history of context
        self.chat_history = tk.Text(self.window)
        self.chat_history.place(relx=0.02, rely=0.17, relheight=0.7, relwidth=0.7)
        self.chat_history.configure(state='disabled', bg='grey20', fg='white')

        # display currently user listbox
        self.username_list = tk.Listbox(self.window)
        self.username_list.place(relx=0.75, rely=0.17, relheight=0.7, width=115)
        self.username_list.configure(bg='grey20', fg='white')

        # display currently user context
        self.label2 = tk.Label(self.window)
        self.label2.place(relx=0.79, rely=0.1, height=20, width=80)
        self.label2.configure(text="Online List", font=("Arial", 12), bg='light slate gray')

        # display entry message box
        self.entry_message = tk.Entry(self.window)
        self.entry_message.place(relx=0.02, rely=0.9, height=24, relwidth=0.6)
        self.entry_message.configure(textvariable=self.message, bg='grey20', fg='white')

        # display send message button
        self.button_send_message = tk.Button(self.window)
        self.button_send_message.place(relx=0.63, rely=0.9, height=24, width=45)
        self.button_send_message.configure(text='發送', font=("Arial", 12), bg='light slate gray')

        # display send file button
        self.button_send_file = tk.Button(self.window)
        self.button_send_file.place(relx=0.75, rely=0.9, height=24, width=115)
        self.button_send_file.configure(text='傳送檔案', font=("Arial", 12), bg='light slate gray', state='disabled')

    # show the login window
    def show(self):
        self.window.mainloop()

    # not show the login window
    def destroy(self):
        try:
            self.turn_off()
        except:
            pass
        self.window.destroy()

    # ask user for quit window event
    def on_closing(self):
        if messagebox.askokcancel("Quit", "Do you want to quit the chat?"):
            self.window.destroy()

# ================================================== Button Event ======================================================


def on_button_login_clicked():

    global client_socket, username, login_window, main_window, udp_socket

    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)   # open TCP socket
    client_socket.settimeout(5)  # 設置連線逾時5秒

    if login_window.username.get() != '' and login_window.password != '':
        client_socket.connect((HOST, PORT))
        encryption.send(client_socket, {'cmd': 'login', 'user': login_window.username.get(),
                                        'password': hashlib.sha1(
                                            login_window.password.get().encode('utf-8')).hexdigest()})

        server_response = encryption.recv(client_socket)

        # 若帳密正確，則初始化main_window狀態，並打開main_window畫面
        if server_response['response'] == 'ok':
            username = login_window.username.get()
            login_window.destroy()
            main_window = MainWin()

            # initialize main_window state
            main_window.username.set(username)
            main_window.button_send_message.configure(command=on_button_send_message_clicked)
            main_window.button_send_file.configure(command=on_button_send_file_clicked)
            main_window.username_list.bind('<<ListboxSelect>>', online_session_select)
            encryption.send(client_socket, {'cmd': 'get_users'})
            encryption.send(client_socket, {'cmd': 'get_history', 'peer': ''})

            # open UDP socket
            udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            udp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

            # multicast setting
            udp_socket.bind(("", MCAST_PORT))  # UDP bind
            mreq = struct.pack("4sl", socket.inet_aton(MCAST_GRP), socket.INADDR_ANY)
            udp_socket.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)

            # open recv_tcp_message_thread
            recv_tcp_thread = threading.Thread(target=recv_tcp_async, args=())
            recv_tcp_thread.setDaemon(True)
            recv_tcp_thread.start()

            # get client_socket information
            print(client_socket)

            # show the chat window
            main_window.show()

        # 若帳密不正確，則顯示failed
        elif server_response['response'] == 'fail':
            tk.messagebox.showerror("Warning! ", "Login failed: " + server_response['reason'])

    else:
        tk.messagebox.showerror("Warning! ", "Account and Password cannot be empty! ")


def on_button_register_clicked():

    global client_socket, login_window

    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.settimeout(5)

    if login_window.username.get() != '' and login_window.password.get() != '':
        client_socket.connect((HOST, PORT))
        encryption.send(client_socket, {'cmd': 'register', 'user': login_window.username.get(),
                                        'password': hashlib.sha1(
                                            login_window.password.get().encode('utf-8')).hexdigest()})

        server_response = encryption.recv(client_socket)
        if server_response['response'] == 'ok':
            tk.messagebox.showinfo("Notification! ", "Register Successfully! ")
        elif server_response['response'] == 'fail':
            tk.messagebox.showerror("Warning! ", "Register failed: " + server_response['reason'])
    else:
        tk.messagebox.showerror("Warning! ", "Account and Password cannot be empty! ")

    close_socket()


def on_button_send_message_clicked():

    global client_socket, username, current_connect_session, main_window

    if main_window.message.get() != '':
        encryption.send(client_socket, {'cmd': 'chat', 'peer': current_connect_session,
                                        'message': main_window.message.get()})
        append_message_to_history(username, time.strftime('%m/%d %Y - %H:%M:%S', time.localtime(time.time())),
                                  main_window.message.get())
        main_window.message.set('')
    else:
        tk.messagebox.showinfo("Warning! ", "Input cannot be empty! ")


def on_button_send_file_clicked():

    global client_socket, main_window, filename, filename_short, file_transfer_waiting

    try:
        filename = tk.filedialog.askopenfilename()
        if filename == '':
            return

        filename_short = ''
        if len(filename.split('/')) < len(filename.split('\\')):
            filename_short = filename.split('\\')[-1]
        else:
            filename_short = filename.split('/')[-1]
        file_size = os.path.getsize(filename)

        count = 0
        while not 1 < file_size < 1024 and count < 6:
            file_size /= 1024
            count += 1
        file_size = str(format(file_size, '.2f')) + ['B', 'KB', 'MB', 'GB', 'TB', 'PB'][count]

        md5_checksum = get_file_md5(filename)
        encryption.send(client_socket, {'cmd': 'file_request', 'peer': current_connect_session,
                                        'filename': filename_short, 'size': file_size, 'md5': md5_checksum})
        main_window.button_send_file.configure(text="Waiting...", state='disabled')

        file_transfer_waiting = True
    except:
        sys.exit(1)


# =================================================== Mouse Event ======================================================

def online_session_select(event):

    global current_connect_session, main_window, username, users, file_transfer_waiting

    widget = event.widget
    changed = False
    if len(widget.curselection()) != 0:
        index = int(widget.curselection()[0])

        if index != 0:
            # set the new message icon('( new)') at the end of the sender
            if current_connect_session != widget.get(index).rstrip(' (*)'):
                changed = True
                current_connect_session = widget.get(index).rstrip(' (*)')
                if not file_transfer_waiting:
                    main_window.button_send_file.configure(state='normal')
                main_window.username.set('%s -> %s' % (username, current_connect_session))
                users[current_connect_session] = False
                refresh_username_list()
        elif index == 0:
            if current_connect_session != '':
                changed = True
                current_connect_session = ''
                main_window.button_send_file.configure(state='disabled')
                main_window.username.set('%s -> global' % username)
                users[''] = False
                refresh_username_list()

        if changed:
            encryption.send(client_socket, {'cmd': 'get_history', 'peer': current_connect_session})


# ================================================ Additional Function =================================================

def append_message_to_history(sender, send_time, message):
    main_window.chat_history['state'] = 'normal'
    main_window.chat_history.insert('end', '%s - %s\n' % (sender, send_time))
    main_window.chat_history.insert('end', message + '\n\n', 'text')
    main_window.chat_history.see('end')
    main_window.chat_history['state'] = 'disabled'


def refresh_username_list():
    main_window.username_list.delete(0, 'end')
    for user in users.keys():
        name = "公頻聊天室" if user == '' else user
        if users[user]:
            name += ' (*)'
        main_window.username_list.insert('end', name)


def close_socket():
    encryption.send(client_socket, {'cmd': 'close'})
    client_socket.shutdown(2)
    client_socket.close()
    udp_socket.close()


# 將要傳送的檔案進行十六進位轉換，再進行MD5加密
def get_file_md5(file_path):

    md5_object = hashlib.md5()
    max_buffer = 8192
    file = open(file_path, 'rb')
    while True:
        buffer = file.read(max_buffer)
        if not buffer:
            break
        md5_object.update(buffer)
    file.close()
    hash = md5_object.hexdigest()
    return str(hash).upper()


# ================================================ Recv Message Event ==================================================

def recv_tcp_async():

    global udp_socket, client_socket, users, main_window, current_connect_session, file_transfer_waiting, filename_short, filename

    while True:

        data = encryption.recv(client_socket)

        # 獲取user清單
        if data['type'] == 'get_users':
            users = {}
            for user in [''] + data['data']:
                users[user] = False
            refresh_username_list()

        # 獲取聊天紀錄
        elif data['type'] == 'get_history':
            if data['peer'] == current_connect_session:
                # delete the old chat_history
                main_window.chat_history['state'] = 'normal'
                main_window.chat_history.delete('1.0', 'end')
                main_window.chat_history['state'] = 'disabled'
                # append new chat_history and display the new chat_history
                for entry in data['data']:
                    append_message_to_history(entry[0], entry[1], entry[2])

        # 新client加入聊天室
        elif data['type'] == 'peer_joined':
            users[data['peer']] = False
            refresh_username_list()

            # multicast
            recv_message = udp_socket.recv(10240).decode()
            print("user: %s, joined the chat" % recv_message)

        # 有client離開聊天室
        elif data['type'] == 'peer_left':

            # multicast
            recv_message = udp_socket.recv(10240).decode()
            print("user: %s, left the chat" % recv_message)

            if data['peer'] in users.keys():
                del users[data['peer']]
            if data['peer'] == current_connect_session:
                current_connect_session = ''
                main_window.button_send_file.configure(state='disabled')
                main_window.username.set('%s -> global' % username)
                users[''] = False
                encryption.send(client_socket, {'cmd': 'get_history', 'peer': ''})
            refresh_username_list()

        # 新訊息
        elif data['type'] == 'message':
            if data['peer'] == current_connect_session:
                append_message_to_history(data['peer'], time.strftime('%m/%d %Y - %H:%M:%S', time.localtime(time.time()))
                                          , data['message'])
            else:
                users[data['peer']] = True
                refresh_username_list()

        # broadcast
        elif data['type'] == 'broadcast':
            if current_connect_session == '':
                append_message_to_history(data['peer'],
                                          time.strftime('%m/%d %Y - %H:%M:%S', time.localtime(time.time()))
                                          , data['message'])
            else:
                users[''] = True
                refresh_username_list()

        # 接收文件
        elif data['type'] == 'file_request':
            # Accept the file
            if tk.messagebox.askyesno("Notification! ", "%s want to send a file to you\n Filename: %s\ndata size: %s\n "
                                      "Accept the file? " % (data['peer'], data['filename'], data['size'])):
                encryption.send(client_socket, {'cmd': 'file_accept', 'peer': data['peer']})
                try:
                    total_file_bytes = 0

                    addr = ('127.0.0.1', 8888)
                    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    server.bind(addr)
                    server.listen(5)

                    client_file_socket, addr = server.accept()

                    # 計算接收檔案的時間
                    start_recv_time = time.time()
                    with open(data['filename'], 'wb') as file:
                        while True:
                            fdata = client_file_socket.recv(1024)
                            total_file_bytes += len(fdata)
                            if not fdata:
                                break
                            file.write(fdata)
                    file.close()
                    client_file_socket.close()
                    server.close()
                    end_recv_time = time.time()

                    # check filename
                    received_md5 = get_file_md5(data['filename'])
                    if received_md5 == str(data['md5']):
                        tk.messagebox.showinfo("Notification !", "File take successfully !")

                    # append send file message to chat_history
                    main_window.chat_history['state'] = 'normal'
                    main_window.chat_history.insert('end', 'Received %s bytes from %s in %s seconds\n\n' %
                                                    (total_file_bytes, data['peer'], format(end_recv_time -
                                                                                            start_recv_time, '.2f'))
                                                    , 'hint')
                    main_window.chat_history.see('end')
                    main_window.chat_history['state'] = 'disabled'
                except:
                    pass
            # deny the file accept request
            else:
                encryption.send(client_socket, {'cmd': 'file_deny', 'peer': data['peer']})

        # 拒絕接收文件
        elif data['type'] == 'file_deny':
            main_window.button_send_file.configure(text="傳送檔案")
            if current_connect_session == '':
                main_window.button_send_file.configure(state='disabled')
            else:
                main_window.button_send_file.configure(state='disabled')
            tk.messagebox.showinfo("Notification !", "Receiver denied to accept the file ! ")

        # 傳送文件
        elif data['type'] == 'file_accept':
            try:
                total_file_bytes = 0

                addr = (data['ip'], 8888)
                client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                client.connect(addr)

                # 計算傳送檔案的時間
                start_send_time = time.time()
                with open(filename, 'rb') as file:
                    while True:
                        fdata = file.read(1024)
                        if not fdata:
                            break
                        total_file_bytes += len(fdata)
                        # client.send(fdata)
                        client.send(fdata)
                file.close()
                client.close()
                end_send_time = time.time()

                # append send file message to chat_history
                main_window.chat_history['state'] = 'normal'
                main_window.chat_history.insert('end', 'Send %s bytes in %s seconds\n\n' %
                                                (total_file_bytes, format(end_send_time - start_send_time, '.2f')),
                                                'hint')
                main_window.chat_history.see('end')
                main_window.chat_history['state'] = 'disabled'
            finally:
                filename = ''
                filename_short = ''
                file_transfer_waiting = False

            main_window.button_send_file.configure(text='傳送檔案')
            if current_connect_session == '':
                main_window.button_send_file.configure(state='disabled')
            else:
                main_window.button_send_file.configure(state='normal')
            tk.messagebox.showinfo("Notification ! ", "File send successfully ! ")


def main():

    global login_window
    login_window = LoginWin()
    login_window.button_login.configure(command=on_button_login_clicked)
    login_window.button_register.configure(command=on_button_register_clicked)
    login_window.show()


if __name__ == '__main__':
    main()
