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


