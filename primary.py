import socket
import socketutil
import time
import random
import cloud
import threading

http_port = 80
proto_port = 9299
self_host = ""
known_contacts = []
current_jobs = {}
outsourced_jobs = {}
nodes_in_network = 1


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


def request_id_gen():
    chars = "abcdefghijklmnopqrstuvwxyz1234567890"
    result = ""
    for i in range(8):
        result.join(random.choice(chars))
    return result

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


def send_proto_message(message, target):
    addr = (target, proto_port)
    s = socketutil.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(10)
    try:
        s.connect(addr)
    except socket.timeout:
        print("ERROR: Attempted to open socket to target %s:%d, but it did not respond!" % (target, proto_port))
        return False

    s.sendall(message)

    try:
        while True:
            response = s.recv_str_until("eot")
            if response.startswith("okay") or response.startswith("contact"):
                break
            s.sendall(message)
        s.close()
        return True
    except socket.timeout:
        print("ERROR: Other node did not send a response in time!")
        return False


def handle_proto_message(sock, client):
    received_message = sock.recv_str_until("eot")
    message_parts = received_message.splitlines()
    print("Received new message from %s via port %d" % (client[0], client[1]))
    print("-----")
    for s in message_parts:
        print(s)
    print("-----")
    send_okay = True
    send_headcount = False
    global nodes_in_network

    if received_message.startswith("okay"):
        # prevents infinite loops of okay responses
        send_okay = False

    elif received_message.startswith("hello"):
        if len(known_contacts) > nodes_in_network/2 and len(known_contacts) > 2:
            send_okay = False
            sock.sendall("contact\n%s\neot" % known_contacts[1])
        else:
            if client[0] not in known_contacts:
                nodes_in_network += 1
                send_headcount = True
                known_contacts.append(client[0])

    elif received_message.startswith("heartbeat"):
        print("Heard a heartbeat from %s!" % client[0])

    elif received_message.startswith("goodbye"):
        if client[0] in known_contacts:
            known_contacts.remove(client[0])

    elif received_message.startswith("headcount"):
        nodes_in_network = int(message_parts[1])
        print("Adjusted headcount is now: %d" % nodes_in_network)

    elif received_message.startswith("contact"):
        send_hello(message_parts[1])

    if send_okay is True:
        sock.sendall("okay\neot")
    sock.close()

    if send_headcount is True:
        for so in known_contacts:
            send_proto_message("headcount\n%d\neot" % nodes_in_network, so)


def handle_http_request(sock, client):
    print("LMAO WE DON'T DO THAT YET!")
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

