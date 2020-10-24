import socket
import socketutil
import time
import cloud
import threading

http_port = 80
proto_port = 9299
self_host = ""


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
        return

    s.sendall(message)

    try:
        response = s.recv_until("eot")
        while response != "okay":
            s.sendall(message)
        s.close()
    except socket.timeout:
        print("ERROR: Other node did not send a response in time!")


def handle_proto_message(sock):
    received_message = sock.recv_until("eot")
    print("RECEIVED A NEW MESSAGE!")
    print(received_message)
    if received_message.startswith("okay"):
        return

    sock.sendall("okay\neot")
    sock.close()


def send_http_request(req, target, sendport):
    addr = (target, sendport)
    s = socketutil.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(addr)
    data = req.method + " " + req.path + " " + req.version + "\r\n"
    data += "Host: "+target
    data += "\r\n\r\n"
    print(data)

    s.sendall(data)
    starttime = time.monotonic()
    print("Start Time: " + str(starttime))
    print("Sent data, awaiting response...")
    responsedata = s.recv_until("\r\n\r\n")
    if responsedata is None:
        return
    endtime = time.monotonic()
    print("End Time: " + str(endtime))
    print("Response received!")

    duration = endtime - starttime

    print()
    print(responsedata.decode())
    duration = duration * 1000
    print()
    print("Raw Time Elapsed: "+str(duration))
    print("Approx. Time Elapsed (rtt): "+str(round(duration, 2)) + "ms")


self_host = cloud.gcp_get_my_external_ip()
print("Currently hosting via: "+str(self_host))
server_addr = ("", proto_port)
listener = socketutil.socket(socket.AF_INET, socket.SOCK_STREAM)
listener.bind(server_addr)
listener.listen()

target = input("Please input the address of a known node, or press enter if this is the first in the network: ")

if target != "":
    message = "hello\n"
    message += "eot"
    send_proto_message(message, target)

try:
    print("Now listening on address %s:%d" % (self_host, proto_port))
    while True:
        sock, client_addr = listener.accept()
        print("New connection established with %s!" % str(client_addr))
        t = threading.Thread(target=handle_proto_message, args=sock)
        t.daemon = True
        t.start()
finally:
    print("Shutting down!")
    listener.close()






