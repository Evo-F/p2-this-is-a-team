import socket
import socketutil
import time
import cloud
import threading

http_port = 80
proto_port = 9299
self_host = ""
known_contacts = []


class HTTPRequest:
    def __init__(self):
        self.method = ""
        self.path = ""
        self.version = ""
        self.headers = []
        self.length = 0
        self.body = None


class HTTPResponse:
    def __init__(self, code, mime_type=None, body=None):
        self.code = code
        self.mime_type = mime_type
        self.headers = []
        self.body = body


def parse_url_parts(url):
    parts = []
    url_prot_rem = url.split("://")
    parts.append(url_prot_rem[0])
    url_path_rem = url_prot_rem[1].split("/", 1)
    parts.append(url_path_rem[0])
    if len(url_path_rem) < 2:
        parts.append("/")
    else:
        parts.append("/"+url_path_rem[1])
    return parts


def send_hello(contact):
    if send_proto_message("hello\neot", contact):
        known_contacts.append(contact)
    print("Known contacts are now as follows: ", known_contacts)


def send_proto_message(message, target):
    addr = (target, proto_port)
    s = socketutil.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(10)
    print("Attempting to send message to %s:%d" % (target, proto_port))
    try:
        s.connect(addr)
        print("Connected successfully!")
    except socket.timeout:
        print("ERROR: Attempted to open socket to target %s:%d, but it did not respond!" % (target, proto_port))
        return False

    s.sendall(message)

    try:
        print("Awaiting response...")
        response = s.recv_str_until("eot")
        print("Response received: %s" % response)
        while not response.startswith("okay"):
            s.sendall(message)
            response = s.recv_str_until("eot")
        s.close()
        return True
    except socket.timeout:
        print("ERROR: Other node did not send a response in time!")
        return False


def handle_proto_message(sock, client):
    received_message = sock.recv_str_until("eot")
    print("RECEIVED A NEW MESSAGE!")
    print(received_message)
    if received_message.startswith("hello"):
        known_contacts.append(client[0])
        print("Known contacts are now as follows: ", known_contacts)
    if received_message.startswith("heartbeat"):
        print("Heard a heartbeat from %s!" % client[0])
    if received_message.startswith("okay"):
        return

    print("Sending OKAY response...")
    sock.sendall("okay\neot")
    print("OKAY response sent, closing socket...")
    sock.close()


def handle_http_request(sock, client):
    return


def listen_http():
    try:
        print("Now listening on address %s:%d (HTTP)" % (self_host, http_port))
        while True:
            sock, client_addr = http_listener.accept()
            print("New HTTP connection established with %s!" % str(client_addr))
            t = threading.Thread(target=handle_http_request, args=(sock, client_addr,))
            t.daemon = True
            t.start()
    finally:
        print("Shutting down HTTP!")
        http_listener.close()


def listen_protocol():
    try:
        print("Now listening on address %s:%d (geoloc protocol)" % (self_host, proto_port))
        while True:
            sock, client_addr = listener.accept()
            print("New geoloc connection established with %s!" % str(client_addr))
            t = threading.Thread(target=handle_proto_message, args=(sock, client_addr,))
            t.daemon = True
            t.start()
    finally:
        print("Shutting down geoloc!")
        listener.close()


self_host = cloud.gcp_get_my_external_ip()
print("Currently hosting via: "+str(self_host))
server_addr = ("", proto_port)
http_addr = ("", http_port)
listener = socketutil.socket(socket.AF_INET, socket.SOCK_STREAM)
listener.bind(server_addr)
listener.listen()

http_listener = socketutil.socket(socket.AF_INET, socket.SOCK_STREAM)
http_listener.bind(http_addr)
http_listener.listen()


itarget = input("Please input the address of a known node, or press enter if this is the first in the network: ")

if itarget != "":
    send_hello(itarget)

t_http = threading.Thread(target=listen_http)
print("HTTP thread set up...")

t_geoloc = threading.Thread(target=listen_protocol)
print("Geoloc thread set up...")

t_http.start()
t_geoloc.start()

for co in known_contacts:
    send_proto_message("heartbeat\neot", co)






