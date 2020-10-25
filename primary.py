import socket
import socketutil
import time
import random
import cloud
import threading
import os

http_port = 80
proto_port = 9299
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


def send_ident_report(contact):
    report = "report\n"
    report += cloud.provider + "\n"
    report += cloud.zone + "\n"
    report += cloud.city + "\n"
    report += "eot"
    send_proto_message(report, contact)


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
    print("Received new message from %s via port %d // message text follows:" % (client[0], client[1]))
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
        if len(known_contacts)+1 > nodes_in_network+1/2 and len(known_contacts)+1 > 2:
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
            nodes_in_network -= 1
            send_headcount = True

    elif received_message.startswith("headcount"):
        nodes_in_network = int(message_parts[1])
        print("Adjusted headcount is now: %d" % nodes_in_network)

    elif received_message.startswith("contact"):
        send_hello(message_parts[1])

    elif received_message.startswith("ident"):
        for kc in known_contacts:
            if kc != client[0]:
                # propagate the message to all other known contacts!
                send_proto_message(received_message+"eot", kc)
        send_ident_report(message_parts[1])

    elif received_message.startswith("report"):
        print("NEW IDENTITY REPORT: %s via %s // %s // %s" % (client[0], message_parts[1],
                                                              message_parts[2], message_parts[3]))

    if send_okay is True:
        sock.sendall("okay\neot")
    sock.close()

    if send_headcount is True:
        for kc in known_contacts:
            send_proto_message("headcount\n%d\neot" % nodes_in_network, kc)


def handle_http_request(sock, client):
    print("New HTTP request from client %s:%d" % (client[0], client[1]))
    request = sock.recv_str_until("\r\n\r\n")
    request_lines = request.splitlines()
    req = HTTPRequest()

    request_root = request_lines[0]
    request_root_args = request_root.split()

    req.method = request_root_args[0]
    req.path = request_root_args[1]
    req.version = request_root_args[2]

    print("Method: %s | Path: %s | Version: %s" % (req.method, req.path, req.version))

    resp = HTTPResponse()

    if req.method == "GET":
        req.path = "/form.html"
        resp = serve_html_file(req.path)
    else:
        resp.code = "405 METHOD NOT ALLOWED"
        resp.mime_type = "text/plain"
        resp.body = "We don't support non-GET methods!"

    send_http_response(sock, resp)


def send_http_response(sock, resp):
    data = "HTTP/1.1 " + resp.code + "\r\n"
    data += "Server: " + cloud.dnsname + "\r\n"
    data += "Data: " + time.strftime("%a, %d %b %Y %H:%M:%S %Z") + "\r\n"

    data += "Content-Type: " + resp.mime_type + "\r\n"
    data += "Content-Length: " + str(len(resp.body)) + "\r\n"
    data += "Connection: close\r\n"
    sock.sendall(data.encode())
    sock.sendall(resp.body)


def serve_html_file(path):
    print("Serving HTTP file...")
    file_path = "./web" + path
    file_path = os.path.normpath(file_path)
    if os.path.commonprefix([file_path, "./web"]) != "./web":
        print("Path traversal attack!")
        return HTTPResponse("403 FORBIDDEN", "text/plain", "Permission denied: " + path)
    if not os.path.isfile(file_path):
        print("File not found!")
        return HTTPResponse("404 NOT FOUND", "text/plain", "No such file: " + path)
    try:
        with open(file_path, "rb") as f:
            data = f.read()
        return HTTPResponse("200 OK", "text/html", data)
    except:
        print("File read error!")
        return HTTPResponse("403 FORBIDDEN", "text/plain", "Permission denied: " + path)


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
t_http.daemon = True
print("HTTP thread set up...")

t_geoloc = threading.Thread(target=listen_protocol)
t_geoloc.daemon = True
print("Geoloc thread set up...")

t_http.start()
t_geoloc.start()

while True:
    user_input = input()
    if user_input.startswith("quit"):
        print("Understood, terminating program...")
        for so in known_contacts:
            send_proto_message("goodbye\neot", so)
        break
    elif user_input.startswith("count"):
        print("There are currently [%d] nodes in the network." % nodes_in_network)
    elif user_input.startswith("heartbeat"):
        print("Sending a heartbeat to all known contacts...")
        for so in known_contacts:
            send_proto_message("heartbeat\neot", so)
        print("Heartbeat sent.")
    elif user_input.startswith("contacts"):
        print("Here are all the known contacts:")
        for so in known_contacts:
            print("- %s" % so)
        print("[[end listing]]")
    elif user_input.startswith("ident"):
        print("Retrieving identifying information...")
        for so in known_contacts:
            send_proto_message("ident\n%s\neot" % self_host, so)
        print("Sent ident request, expect results shortly.")

print("All known contacts notified. Node terminated.")
