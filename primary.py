import socket
import socketutil
import time
import random
import cloud
import threading
import urllib

http_port = 80
proto_port = 9299
known_contacts = []
all_nodes_listified = ""
current_jobs = []
gathered_results = {}
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


class GeolocResults:
    def __init__(self, rtt, size):
        self.target = ""
        self.rtt = rtt
        self.size = size


def request_id_gen():
    result = ""
    for i in range(8):
        result += str(random.randint(0, 9))
    return result


def process_results(job_id):
    global gathered_results
    r_list = ""
    data = ""
    for host in gathered_results[job_id]:
        res = gathered_results[job_id][host]
        data = "%s // RTT: %d // SIZE: %d" % (host, res.rtt, res.size)
        data += "\n"
        r_list += data
    return r_list


def process_specific_url(url):
    parts = parse_url_parts(url)
    if parts[0] == "https":
        return -1, -1

    addr = (socket.gethostbyname(parts[1]), http_port)
    print("Attempting to ping %s:%d" % (addr[0], addr[1]))

    target_url_sock = socketutil.socket(socket.AF_INET, socket.SOCK_STREAM)
    target_url_sock.settimeout(10)
    try:
        target_url_sock.connect(addr)
    except:
        return -1, -1

    ping_request = "HEAD %s HTTP/1.1\r\n" % parts[2]
    ping_request += "Host: " + parts[1] + "\r\n\r\n"
    print("Sent Request:\n-----")
    print(ping_request)
    print("-----")
    target_url_sock.sendall(ping_request)
    starttime = time.monotonic()
    try:
        response = target_url_sock.recv_str_until("\r\n\r\n")
        endtime = time.monotonic()
        print("-----")
        print(response)
        print("-----")
    except:
        return -1, -1

    duration = endtime - starttime
    duration = duration * 1000
    print("Duration: %dms" % duration)
    response_lines = response.split("\r\n")
    size = 0;
    for line in response_lines:
        if line.startswith("Content-Length:"):
            size = int(line.split(": ", 1)[1])
            break
        if line == "Transfer-Encoding: chunked":
            size = -1
            break
    return duration, size


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


def process_job():
    global current_jobs
    global gathered_results
    print("Started process_job loop....")

    while True:
        while not current_jobs:
            # spin until we have a job to do
            pass
        for job in current_jobs:
            print("Began new job!")
            rtt, size = process_specific_url(job[1])

            print("RTT: %d, SIZE: %d" % (rtt, size))
            res = GeolocResults(rtt, size)
            res.target = job[1]

            if job[2] == self_host:
                # we just did our own job and got some results for it
                gathered_results[job[0]][self_host] = res
            else:
                # we did somebody else's job and now we need to send the results
                send_results(job[2], res, job[0])

            current_jobs.remove(job)


def send_hello(contact):
    if send_proto_message("hello\neot", contact):
        known_contacts.append(contact)


def send_results(contact, results, id):
    message = "result\n"
    message += id + "\n"
    message += results.target + "\n"
    message += results.rtt + "\n"
    message += results.size + "\n"
    message += "eot"
    send_proto_message(message, contact)


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
            if response.startswith("okay"):
                break
            if response.startswith("contact"):
                return False
            s.sendall(message)
        s.close()
        return True
    except socket.timeout:
        print("ERROR: Other node did not send a response in time!")
        return False


def request_ident():
    for so in known_contacts:
        send_proto_message("ident\n%s\neot" % self_host, so)


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
        send_headcount = True
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
        global all_nodes_listified
        print("NEW IDENTITY REPORT: %s via %s // %s // %s" % (client[0], message_parts[1],
                                                              message_parts[2], message_parts[3]))
        all_nodes_listified += "%s via %s // %s // %s" % (client[0], message_parts[1],
                                                          message_parts[2], message_parts[3])
        all_nodes_listified += "\n"

    elif received_message.startswith("result"):
        job_id = message_parts[1]
        reported_rtt = float(message_parts[3])
        reported_size = int(message_parts[4])
        reporting_node = client[0]
        res = GeolocResults(reported_rtt, reported_size)
        res.target = message_parts[2]
        gathered_results[job_id][reporting_node] = res

    elif received_message.startswith("request"):
        job_id = message_parts[1]
        target = message_parts[2]
        requester = message_parts[3]
        current_jobs.append((job_id, target, requester))

    if send_okay is True:
        sock.sendall("okay\neot")
    sock.close()

    if send_headcount is True:
        for kc in known_contacts:
            if kc != client[0]:
                send_proto_message("headcount\n%d\neot" % nodes_in_network, kc)


def handle_http_request(sock, client):
    print("New HTTP request from client %s:%d" % (client[0], client[1]))
    request = sock.recv_str_until("\r\n\r\n")
    print("-----")
    print(request)
    print("-----")
    request_lines = request.splitlines()
    req = HTTPRequest()

    request_root = request_lines[0]
    request_root_args = request_root.split()

    keepalive = False

    for s in request_lines:
        if s.startswith("Connection") and s.endswith("keep-alive"):
            keepalive = True
            break

    req.method = request_root_args[0]
    req.path = request_root_args[1]
    req.version = request_root_args[2]

    print("Method: %s | Path: %s | Version: %s" % (req.method, req.path, req.version))

    if req.method == "GET":
        resp = serve_html_file(req.path)
    else:
        resp = HTTPResponse("405 METHOD NOT ALLOWED")
        resp.mime_type = "text/plain"
        resp.body = "We don't support non-GET methods!"

    send_http_response(sock, resp, keepalive)


def send_http_response(sock, resp, keepalive):
    data = "HTTP/1.1 " + resp.code + "\r\n"
    data += "Server: " + cloud.dnsname + "\r\n"
    data += "Date: " + time.strftime("%a, %d %b %Y %H:%M:%S %Z") + "\r\n"

    data += "Content-Type: " + resp.mime_type + "\r\n"
    data += "Content-Length: " + str(len(resp.body)) + "\r\n"
    if keepalive is True:
        data += "Connection: keep-alive\r\n"
    else:
        data += "Connection: close\r\n"
    data += "\r\n"

    print("Sending the following response:")
    print("-----")
    print(data)
    print(resp.body)
    print("-----")
    sock.sendall(data.encode())
    sock.sendall(resp.body)


def serve_html_file(path):
    global gathered_results
    global nodes_in_network
    if path.startswith("/analyze"):
        analysis_args = path.split("?", 1)[1]
        analysis_args = urllib.parse.unquote(analysis_args)
        analysis_target = ""
        print(analysis_args)
        analysis_args = analysis_args.split("&")
        for s in analysis_args:
            if s.startswith("target="):
                analysis_target = s.split("=")[1]
                break
        request_id = request_id_gen()
        print("Request ID: " + request_id)

        global gathered_results
        gathered_results[request_id] = {}

        current_jobs.append((request_id, analysis_target, self_host))
        print("Appended new job.")

        message = "request\n"
        message += request_id + "\n"
        message += analysis_target +"\n"
        message += self_host + "\n"
        message += "eot"

        for kc in known_contacts:
            send_proto_message(message, kc)

        print("Waiting for results...")
        while len(gathered_results[request_id]) < nodes_in_network:
            pass
        print("All results are in (%d)!" % len(gathered_results[request_id]))
        return serve_analysis(request_id)

    return serve_index()


def serve_analysis(request_id):
    global self_host
    print("Attempting to serve analysis page...")
    try:
        print("Trying to read file...")
        with open("web/analysis.html", "rb") as f:
            data = f.read()
        print("File read! Processing results...")
        listified_results = process_results()
        print("Processed results!")
        print(listified_results)
        datastring = data.decode()
        datastring = datastring.format(hostname=gathered_results[request_id][self_host].target,
                                       results=listified_results)
        data = datastring.encode()
        return HTTPResponse("200 OK", "text/html", data)
    except:
        print("File read error!")
        return HTTPResponse("403 FORBIDDEN", "text/plain", "File read error: web/analysis.html")

    return serve_index()


def serve_index():
    global all_nodes_listified
    all_nodes_listified = ""
    all_nodes_listified += "[*] %s via %s // %s // %s" % (self_host, cloud.provider, cloud.zone, cloud.city)
    all_nodes_listified += "\n"
    request_ident()
    try:
        with open("web/form.html", "rb") as f:
            data = f.read()

        datastring = data.decode()
        datastring = datastring.format(currentserver=cloud.dnsname,
                                       servercount=nodes_in_network,
                                       serverlist=all_nodes_listified)
        data = datastring.encode()
        return HTTPResponse("200 OK", "text/html", data)
    except:
        print("File read error!")
        return HTTPResponse("403 FORBIDDEN", "text/plain", "Permission denied: web/form.html")


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
listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
listener.bind(server_addr)
listener.listen()

http_listener = socketutil.socket(socket.AF_INET, socket.SOCK_STREAM)
http_listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
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

t_worker = threading.Thread(target=process_job)
t_worker.daemon = True
print("Worker thread set up...")

t_http.start()
t_geoloc.start()
t_worker.start()

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

