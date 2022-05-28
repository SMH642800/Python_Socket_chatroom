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
