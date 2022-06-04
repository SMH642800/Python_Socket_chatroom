# 網路程式設計 Final Project
## 1. Project題目
- 利用Python tkinter和Python socket實做簡單版多人聊天室

## 2. Project內容
- 利用python tkinter modual設計聊天室的UI。
- 有帳號及密碼的註冊及登錄功能，並且在登錄時會進行核對帳密的動作。
- 聊天室分為公共頻道與私人頻道，可以透過右側listbox欄位來選擇要在哪一個頻道進行發言。
- 用戶之間可以進行傳送檔案(包括圖片、文件等)動作。
- 會保存聊天室紀錄，並在下次登陸時會載入之前的聊天紀錄
- 聊天室在網路上之間的對話傳送，皆利用Python Crypto module中的AES加密演算法進行加密

## 3. 執行畫面
- 帳號註冊及登錄畫面:
    ![](https://i.imgur.com/kzLccDv.png)
    
- 聊天室主畫面:
    ![](https://i.imgur.com/aQ90B1u.png)
    
- 聊天室會顯示發送訊息當下的時間點:
    ![](https://i.imgur.com/dcaEbCB.png)
    
- 可以選擇要跟哪一位用戶進行一對一對話，而當聊天室有新的訊息時，會在用戶清單旁顯示“(new)”的標示:
    ![](https://i.imgur.com/QRG6MWp.png)
    
- 按下傳送檔案後，會跳出選擇檔案的畫面，選擇完檔案後，會先詢問對方是否願意接收檔案，若對方願意接受，則檔案會傳送過去給對方:
    ![](https://i.imgur.com/SbmHqK2.png)
    ![](https://i.imgur.com/2XFavlL.png)
    ![](https://i.imgur.com/5lmEGMd.png)
    ![](https://i.imgur.com/IYkU3af.png)
    ![](https://i.imgur.com/RQ2COWx.png)
    
- 當有成員加入聊天室或離開聊天室，server都會透過UDP，利用multicast向仍在線上的所有user進行通知:
    ![](https://i.imgur.com/3yp6rzW.png)
    
- 當用戶傳送訊息時，會透過AES加密，並且在server端解密之後在加密一次傳送給所有在線的user:
    ![](https://i.imgur.com/C6xyaGe.png)
    
## 4. Project source code
1. encryption & decryption
    ```python
    from Crypto.Cipher import AES
    from Crypto import Random

    key = b'fdj27pFJ992FkHQb'

    def encrypt(data):

        code = Random.new().read(AES.block_size)
        cipher = AES.new(key, AES.MODE_CFB, code)

    return code + cipher.encrypt(data)


    def decrypt(data):
        return AES.new(key, AES.MODE_CFB, data[:16]).decrypt(data[16:])
    ```

2. Socket's Send & Recv
    - 發送package前會在最前頭加上明確地package size的一個2 byte('>H')。
    - 接收package時先接收這個2 byte('>H')，獲取將要接收的package，然後再接收相對應size的package。
    ```python
    import struct
    import json

    max_buff_size = 1024

    def pack(data):
        return struct.pack('>H', len(data)) + data


    def send(socket, data_dict):
        socket.send(pack(encrypt(json.dumps(data_dict).encode('utf-8'))))


    def recv(socket):
        data = b''
        surplus = struct.unpack('>H', socket.recv(2))[0]
        socket.settimeout(5)

        while surplus:
            recv_data = socket.recv(max_buff_size if surplus > max_buff_size else surplus)
            data += recv_data
            surplus -= len(recv_data)

        socket.settimeout(None)

        return json.loads(decrypt(data))
    ```
    
3. 帳號管理相關的function
    - 包刮從文件(users.dat)中加載已註冊users的帳密資料（賬號和密碼對應的MD5值）、註冊用戶、驗證用戶（看看密碼的MD5值是否和文件中的值相同）、將所有已註冊用戶的信息保存到文件中。
    ```python
    def load_users():
        try:
            return pickle.load(open('users.dat', 'rb'))  # r: read, b: byte
        except:
            return {}


    def user_certificate(user, password):
        if user in users.keys() and users[user] == password:
            return True
        return False


    def user_register(user, password):
        if user not in users.keys():
            users[user] = password
            save_users()
            return True
        else:
            return False


    def save_users():
        pickle.dump(users, open('users.dat', 'wb'))  # w: write, b: byte

    ```
    
4. 聊天紀錄管理相關的function
    - 每條聊天記錄為key-value形式，key為（sender，receiver），value為（sender，time，msg），包括從文件(chat_history.dat)當中載入聊天紀錄、把聊天紀錄儲存至文件當中
    ```python
    def load_history():
        try:
            return pickle.load(open('chat_history.dat', 'rb'))  # w: write, b: byte
        except:
            return {}


    def get_history(sender, receiver):
        if receiver == '':
            key = ('', '')
        else:
            key = get_key(sender, receiver)
        return chat_history[key] if key in chat_history.keys() else []


    def get_key(sender, receiver):
        return(sender, receiver) if (receiver, sender) not in chat_history.keys() else (receiver, sender)


    def append_history(sender, receiver, message):
        if receiver == '':
            key = ('', '')
        else:
            key = get_key(sender, receiver)

        if key not in chat_history.keys():
            chat_history[key] = []
        chat_history[key].append((sender, time.strftime('%m/%d %Y - %H:%M:%S', time.localtime(time.time())), message))
        save_history()


    def save_history():
        pickle.dump(chat_history, open('chat_history.dat', 'wb'))  # w: write, b: byte
    ```
    
5. Server端
    - 服務端採用socketserver的BaseRequestHandler Class，可自動處理並發送請求。代表每當有一個客戶端請求連接時，都會new一個BaseRequestHandler Class，然後在一個thread中處理相關請求。
    ```python
    class Handler(socketserver.BaseRequestHandler):

        clients = {}

        def setup(self):
            self.user = ''
            self.file_peer = ''
            self.authed = False

        def handle(self):

            while True:
                # ......


    def main():
        global server, users, chat_history, application

        print("Server running...")

        users = load_users()
        chat_history = load_history()

        application = socketserver.ThreadingTCPServer((HOST, PORT), Handler)
        application.serve_forever()


    if __name__ == '__main__':
        main()

    ```
6. multicast
    - 當有成員加入聊天室或離開聊天室，server都會透過利用multicast向仍在線上的所有user進行通知
    - server:
        ```python
        server = None
        MCAST_GRP = '224.111.1.1'
        MCAST_PORT = 5007

        def multicast(user):
            global server
            
            server.sendto(str(user).encode('utf-8'), (MCAST_GRP, MCAST_PORT))
            
        class Handler(socketserver.BaseRequestHandler):

            clients = {}

            def setup(self):
                self.user = ''
                self.file_peer = ''
                self.authed = False

            def handle(self):

                while True:
                    data = encryption.recv(self.request)

                    # multicast to all online client
                    multicast(self.user)
            
        def main():
            global server

            MULTICAST_TTL = 2
            server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            server.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, MULTICAST_TTL)


        if __name__ == '__main__':
            main()
        ```
    - client:
        ```python
        udp_socket = None
        MCAST_GRP = '224.111.1.1'
        MCAST_PORT = 5007

        # open UDP socket
        udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        udp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        # multicast setting
        udp_socket.bind(("", MCAST_PORT))  # UDP bind
        mreq = struct.pack("4sl", socket.inet_aton(MCAST_GRP), socket.INADDR_ANY)
        udp_socket.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
        
        recv_message = udp_socket.recv(10240).decode()
        print("user: %s, join the chat" % recv_message)
        ```

## 5. 參考資料
[1. How do you UDP multicast in Python?](https://stackoverflow.com/questions/603852/how-do-you-udp-multicast-in-python)
[2. 為應用程式設計圖形化介面，使用Python Tkinter 模組](https://www.rs-online.com/designspark/python-tkinter-cn)
[3. 如何使用按鈕設定 Tkinter 文字控制元件的文字](https://www.delftstack.com/zh-tw/howto/python-tkinter/how-to-set-text-of-tkinter-text-widget-by-using-a-button/)
[4. Python - Tkinter Text](https://www.tutorialspoint.com/python/tk_text.htm)
[5. How to avoid tkinter "ListboxSelect" and .curselection() detecting events/selection outside of Listbox?](https://stackoverflow.com/questions/48676325/how-to-avoid-tkinter-listboxselect-and-curselection-detecting-events-sele)
[6. Python tkinter filedialog 開啟檔案對話框](https://shengyu7697.github.io/python-tkinter-filedialog/)
[7. What is the difference between \ and \\\ in file path](https://stackoverflow.com/questions/15969608/what-is-the-difference-between-and-in-file-path)
[8. Python UDP Server/Client 網路通訊教學](https://shengyu7697.github.io/python-udp-socket/)
[9. Python time 時間模組使用教學與範例](https://officeguide.cc/python-time-tutorial-examples/)
[10. time — Time access and conversions](https://docs.python.org/3/library/time.html#time.strftime)
[11. Python資料儲存：pickle模組的使用](https://www.796t.com/content/1541722469.html)
[12. Day11 - Python 如何處理 JSON](https://ithelp.ithome.com.tw/articles/10220160)
[13. struct--- 將字節串解讀為打包的二進制數據](https://docs.python.org/zh-cn/3/library/struct.html)
[14. Python 3的f-Strings：增強的字串格式語法（指南）](https://iter01.com/585538.html)
[15. Python 以 PyCryptodome 實作 AES 對稱式加密方法教學與範例](https://officeguide.cc/python-pycryptodome-aes-symmetric-encryption-tutorial-examples/)
[16. Encrypt & Decrypt using PyCrypto AES 256](https://stackoverflow.com/questions/12524994/encrypt-decrypt-using-pycrypto-aes-256)
[17. Python Crypto.Random類代碼示例](https://vimsky.com/zh-tw/examples/detail/python-ex-Crypto-Random---class.html)
[18. Python 計算 MD5 與 SHA 雜湊教學與範例](https://blog.gtwang.org/programming/python-md5-sha-hash-functions-tutorial-examples/)
[19. How To Use Images as Backgrounds in Tkinter?](https://www.geeksforgeeks.org/how-to-use-images-as-backgrounds-in-tkinter/)
[20. How to change font and size of buttons in Tkinter Python](https://stackhowto.com/how-to-change-font-and-size-of-buttons-in-tkinter-python/)
[21. Python tkinter Entry 文字輸入框用法與範例](https://shengyu7697.github.io/python-tkinter-entry/)
[22. Python 內建 GUI 模組 tkinter 測試 (三) : 版面管理員](http://yhhuang1966.blogspot.com/2018/10/python-gui-tkinter_12.html)

---

## 6. 程式碼
- 注意: 若要執行此程式的話，需要安裝Crypto module，才能夠正常執行 
(可能也需要安裝其他python插件，須依你個人電腦的情況決定)

- Client:
```python
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
            if current_connect_session != widget.get(index).rstrip(' (new)'):
                changed = True
                current_connect_session = widget.get(index).rstrip(' (new)')
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
            name += ' (new)'
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
        if data['type'] == 'broadcast':
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

```
- Server:
```python
import socketserver
import pickle
import socket
import time

import encryption

# ========================================== Default attribute configure ===============================================

MCAST_GRP = '224.111.1.1'
MCAST_PORT = 5007

HOST = '127.111.0.1'
PORT = 12345
LISTENER_LIMIT = 5

users = None
chat_history = None

server = None

application = None


# =========================================== Loading register users data ==============================================

def load_users():
    try:
        return pickle.load(open('users.dat', 'rb'))  # r: read, b: byte
    except:
        return {}


def user_certificate(user, password):
    if user in users.keys() and users[user] == password:
        return True
    return False


def user_register(user, password):
    if user not in users.keys():
        users[user] = password
        save_users()
        return True
    else:
        return False


def save_users():
    pickle.dump(users, open('users.dat', 'wb'))  # w: write, b: byte


# =========================================== Loading chat history data ================================================

def load_history():
    try:
        return pickle.load(open('chat_history.dat', 'rb'))  # w: write, b: byte
    except:
        return {}


def get_history(sender, receiver):
    if receiver == '':
        key = ('', '')
    else:
        key = get_key(sender, receiver)
    return chat_history[key] if key in chat_history.keys() else []


def get_key(sender, receiver):
    return(sender, receiver) if (receiver, sender) not in chat_history.keys() else (receiver, sender)


def append_history(sender, receiver, message):
    if receiver == '':
        key = ('', '')
    else:
        key = get_key(sender, receiver)

    if key not in chat_history.keys():
        chat_history[key] = []
    chat_history[key].append((sender, time.strftime('%m/%d %Y - %H:%M:%S', time.localtime(time.time())), message))
    save_history()


def save_history():
    pickle.dump(chat_history, open('chat_history.dat', 'wb'))  # w: write, b: byte


# ============================================== UDP multicast msg send ==============================================

def multicast(user):
    global server
    server.sendto(str(user).encode('utf-8'), (MCAST_GRP, MCAST_PORT))


# ================================================== Server Handler ====================================================

class Handler(socketserver.BaseRequestHandler):

    clients = {}

    def setup(self):
        self.user = ''
        self.file_peer = ''
        self.authed = False

    def handle(self):

        while True:
            data = encryption.recv(self.request)

            # 尚未登錄帳號
            if not self.authed:
                self.user = data['user']

                # 帳號登陸
                if data['cmd'] == 'login':
                    # 帳密認證
                    if user_certificate(data['user'], data['password']):
                        encryption.send(self.request, {'response': 'ok'})
                        self.authed = True   # 帳密認證成功
                        for user in Handler.clients.keys():
                            encryption.send(Handler.clients[user].request, {'type': 'peer_joined', 'peer': self.user})
                        Handler.clients[self.user] = self

                        # get connected client's socket information
                        print("USER: " + self.user + " --> Socket: " + str(Handler.clients[self.user].request))

                        # multicast to all online client
                        multicast(self.user)

                    else:
                        encryption.send(self.request, {'response': 'fail',
                                                       'reason': "Account or Password not correct ! "})

                # 帳密註冊
                elif data['cmd'] == 'register':
                    if user_register(data['user'], data['password']):
                        encryption.send(self.request, {'response': 'ok'})
                    else:
                        encryption.send(self.request, {'response': 'fail', 'reason': "Account is already existed ! "})

            # 成功登入帳號
            else:

                # 取得目前user的資料
                if data['cmd'] == 'get_users':
                    users = []
                    for user in Handler.clients.keys():
                        # 若是新加入的user，則加到名單內
                        if user != self.user:
                            users.append(user)
                    encryption.send(self.request, {'type': 'get_users', 'data': users})

                # 取得聊天紀錄
                elif data['cmd'] == 'get_history':
                    encryption.send(self.request, {'type': 'get_history', 'peer': data['peer'],
                                                   'data': get_history(self.user, data['peer'])})

                # 取得要傳送至個別聊天室的內容
                elif data['cmd'] == 'chat' and data['peer'] != '':
                    encryption.send(Handler.clients[data['peer']].request, {'type': 'message', 'peer': self.user,
                                                                            'message': data['message']})
                    append_history(self.user, data['peer'], data['message'])

                # 取得要傳送至公頻聊天室的內容
                elif data['cmd'] == 'chat' and data['peer'] == '':
                    for user in Handler.clients.keys():
                        if user != self.user:
                            encryption.send(Handler.clients[user].request, {'type': 'broadcast', 'peer': self.user,
                                            'message': data['message']})
                    append_history(self.user, '', data['message'])

                # 檔案傳送請求
                elif data['cmd'] == 'file_request':
                    Handler.clients[data['peer']].file_peer = self.user
                    encryption.send(Handler.clients[data['peer']].request, {'type': 'file_request', 'peer': self.user,
                                                                            'filename': data['filename'],
                                                                            'size': data['size'], 'md5': data['md5']})

                # 檔案接收拒絕
                elif data['cmd'] == 'file_deny' and data['peer'] == self.file_peer:
                    self.file_peer = ''
                    encryption.send(Handler.clients[data['peer']].request, {'type': 'file_deny', 'peer': self.user})

                # 傳送檔案請求通過
                elif data['cmd'] == 'file_accept' and data['peer'] == self.file_peer:
                    self.file_peer = ''
                    encryption.send(Handler.clients[data['peer']].request, {'type': 'file_accept',
                                                                            'ip': self.client_address[0]})

                # 離開聊天室
                elif data['cmd'] == 'close':
                    self.finish()

    def finish(self):
        if self.authed:
            self.authed = False

            # multicast to all online client
            multicast(self.user)

            if self.user in Handler.clients.keys():
                del Handler.clients[self.user]
            for user in Handler.clients.keys():
                encryption.send(Handler.clients[user].request, {'type': 'peer_left', 'peer': self.user})


def main():
    global server, users, chat_history, application

    print("Server running...")

    # UDP multicast setting
    MULTICAST_TTL = 2
    server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    server.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, MULTICAST_TTL)

    users = load_users()
    chat_history = load_history()

    application = socketserver.ThreadingTCPServer((HOST, PORT), Handler)
    application.serve_forever()


if __name__ == '__main__':
    main()

```
- Encryption: 
```python
from Crypto.Cipher import AES   # 加密演算法-引用AES加密
from Crypto import Random   # produce random encryption key
import struct   # Interpret bytes as packed binary data
import json

max_buffer_size = 2048
key = b'86Y4xTrT2mVMNgdK'   # AES-128 (16 bits)


def encrypt(data):
    code = Random.new().read(AES.block_size)
    cipher = AES.new(key, AES.MODE_CFB, code)
    return code + cipher.encrypt(data)


def decrypt(data):
    code = data[:16]   # get encrypt key
    ciphered_data = data[16:]  # get encrypted data
    cipher = AES.new(key, AES.MODE_CFB, code)
    return cipher.decrypt(ciphered_data)


def pack(data):
    # H: unsigned short (2 bytes)
    # pack(format, v1, v2, ....)
    return struct.pack('>H', len(data)) + data


def send(socket, data_dict):
    # json.dumps = change python object into json string
    socket.send(pack(encrypt(json.dumps(data_dict).encode('utf-8'))))


def recv(socket):
    data = b''
    data_size = struct.unpack('>H', socket.recv(2))[0]
    socket.settimeout(5)

    while data_size:
        recv_data = socket.recv(max_buffer_size if data_size > max_buffer_size else data_size)
        data += recv_data
        data_size -= len(recv_data)
    socket.settimeout(None)

    # json.loads = change json string into python object
    return json.loads(decrypt(data))

```
