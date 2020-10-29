import socket
import socketutil
import time
import random
import cloud
import threading
import urllib

http_port = 80
proto_port = 9299
ping_passes = 5 # how many times the node should "ping" the target for a result
known_contacts = []
all_nodes_listified = ""
current_jobs = []
gathered_results = {}


class HTTPRequest:
    # This code shamelessly borrowed from Project 1.
    def __init__(self):
        self.method = ""
        self.path = ""
        self.version = ""
        self.headers = []
        self.length = 0
        self.body = None


class HTTPResponse:
    # This code shamelessly borrowed from Project 1.
    def __init__(self, code, mime_type=None, body=None):
        self.code = code
        self.mime_type = mime_type
        self.body = body


class GeolocResults:
    def __init__(self, rtt, size):
        self.target = ""
        self.rtt = rtt
        self.size = size
        self.worker_lat = ""
        self.worker_long = ""
        self.worker_name = ""


def request_id_gen():
    result = ""
    for i in range(8):
        result += str(random.randint(0, 9))
    return result


def attempt_connection():
    global self_host
    with open("node_record.txt", "r") as f:
        data = f.read()
        f.close()
    hosts = data.splitlines()
    for hn in hosts:
        if hn == self_host:
            pass
        if send_hello(hn):
            print("Living contact found: %s" % hn)
            break


def save_hosts():
    global known_contacts
    with open("node_record.txt", "r") as f:
        file_hosts = f.read().splitlines()
        f.close()
    with open("node_record.txt", "a") as f:
        for kc in known_contacts:
            if kc not in file_hosts:
                f.write(kc + "\n")
        f.close()


def process_results(job_id):
    global gathered_results
    r_list = ""
    print("Starting to process results!")
    print(gathered_results[job_id].items())

    min_rtt_val = -9.0
    min_rtt_host = ""

    for host in gathered_results[job_id]:
        res = gathered_results[job_id][host]
        if min_rtt_val == -9.0 or res.rtt < min_rtt_val:
            min_rtt_val = res.rtt
            min_rtt_host = host

    for host in gathered_results[job_id]:
        print("Getting some results...")
        res = gathered_results[job_id][host]
        if host == min_rtt_host:
            data = "<tr style=\"background-color:#FFFF00\">"
        else:
            data = "<tr>"
        data += "<td>%s</td>" % res.worker_name
        data += "<td>%s</td>" % host
        data += "<td>%s</td>" % res.target
        data += "<td>%f</td>" % res.rtt
        data += "<td>%f</td>" % (res.rtt * 60.0)

        if res.size == 0:
            data += "<td>Protocol Mismatch (site requires HTTPS)</td>"
        elif res.size == -1:
            data += "<td>HTTP 403 Forbidden (site refused to serve a page)</td>"
        elif res.size == -2:
            data += "<td>Did Not Accept Connection (potential network-level block or filter)</td>"
        elif res.size == -3:
            data += "<td>Error Retrieving Response (node error)</td>"
        elif res.size == -4:
            data += "<td>Chunked Transfer Encoding (nothing's wrong, just means we can't parse the webpage)</td>"
        else:
            data += "<td>%d</td>" % res.size

        data += "<td>%s, %s</td>" % (res.worker_lat, res.worker_long)
        data += "</tr>\n"
        r_list += data
    print("Done getting results!")
    return r_list


def process_specific_url(url):
    parts = parse_url_parts(url)
    addr = (socket.gethostbyname(parts[1]), http_port)
    print("Attempting to ping %s:%d" % (addr[0], addr[1]))

    target_url_sock = socketutil.socket(socket.AF_INET, socket.SOCK_STREAM)
    target_url_sock.settimeout(1)
    try:
        target_url_sock.connect(addr)
    except:
        return -1, -2, addr[0]

    ping_request = "HEAD %s HTTP/1.1\r\n" % parts[2]
    ping_request += "Host: " + parts[1] + "\r\n\r\n"
    print("Sent Request:\n-----")
    print(ping_request)
    print("-----")
    target_url_sock.sendall(ping_request)
    starttime = time.monotonic()
    try:
        response = target_url_sock.recv_str(1)
        endtime = time.monotonic()
        response += target_url_sock.recv_str_until("\r\n\r\n")
        print("-----")
        print(response)
        print("-----")
    except:
        return -1, -3, addr[0]

    duration = endtime - starttime
    duration = duration * 1000.0
    print("Duration: %dms" % duration)
    response_lines = response.split("\r\n")
    size = -3 # if this value doesn't change, it assumes an error on our end
    response_code_pieces = response_lines[0].split(" ")
    if response_code_pieces[1] == "301":
        return duration, 0, addr[0]
    elif response_code_pieces[1] == "403":
        return duration, -1, addr[0]

    for line in response_lines:
        if line.startswith("Content-Length:"):
            reported_size = int(line.split(": ", 1)[1])
            if reported_size > 0:
                size = reported_size
            break
        if line == "Transfer-Encoding: chunked":
            size = -4
            break
    return duration, size, addr[0]


def parse_url_parts(url):
    # parts[0] is always http or https
    # parts[1] is the fully-qualified domain name (www.google.com)
    # parts[2] is the path (/index.html)
    parts = []

    if url.startswith("https://"):
        parts.append("https")
    else:
        parts.append("http")

    if url.startswith("https://"):
        url = url[8:]
    elif url.startswith("http://"):
        url = url[7:]

    split_url = url.split("/", 1)
    parts.append(split_url[0])
    if len(split_url) == 1:
        parts.append("/")
    else:
        parts.append("/" + split_url[1])

    return parts


def process_job():
    global current_jobs
    global gathered_results
    global ping_passes
    print("Started process_job loop....")

    while True:
        while not current_jobs:
            # spin until we have a job to do
            pass
        for job in current_jobs:
            print("Began new job!")
            average_rtt = -1.0
            for i in range(ping_passes):
                rtt, temp_size, temp_target_ip = process_specific_url(job[1])
                if average_rtt < 0.0:
                    average_rtt = rtt
                    size = temp_size
                    target_ip = temp_target_ip
                    # we don't need to keep doing stuff with the size, so once we get it from the first ping,
                    # we can Store And Ignore
                else:
                    average_rtt = (average_rtt + rtt) / 2.0

            print("RTT: %d, SIZE: %d" % (average_rtt, size))
            res = GeolocResults(average_rtt, size)
            res.worker_lat = cloud.coords[0]
            res.worker_long = cloud.coords[1]
            res.target = target_ip
            res.worker_name = cloud.dnsname

            if job[2] == self_host:
                # we just did our own job and got some results for it
                gathered_results[job[0]][self_host] = res
            else:
                # we did somebody else's job and now we need to send the results
                send_results(job[2], res, job[0])

            current_jobs.remove(job)


def send_hello(contact):
    global known_contacts
    global self_host
    if send_proto_message("hello\neot", contact):
        if contact not in known_contacts and contact != self_host:
            known_contacts.append(contact)
        save_hosts()
        return True
    return False


def send_results(contact, results, id):
    message = "result\n"
    message += id + "\n"
    message += results.target + "\n"
    message += str(results.rtt) + "\n"
    message += str(results.size) + "\n"
    message += str(results.worker_lat) + "\n"
    message += str(results.worker_long) + "\n"
    message += cloud.dnsname + "\n"
    message += "eot"
    send_proto_message(message, contact)


def send_ident_report(contact):
    report = "report\n"
    report += cloud.provider + "\n"
    report += cloud.dnsname + "\n"
    report += cloud.zone + "\n"
    report += cloud.city + ", " + cloud.title + "\n"
    report += str(cloud.coords[0]) + "\n"
    report += str(cloud.coords[1]) + "\n"
    report += "eot"
    send_proto_message(report, contact)


def send_proto_message(message, target):
    addr = (target, proto_port)
    s = socketutil.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(1)
    try:
        s.connect(addr)
    except:
        print("[CONN] ERROR Attempted to open socket to target %s:%d, but it did not respond!" % (target, proto_port))
        return False

    print("[CONN] SUCCESS %s:%d" % (target, proto_port))
    s.sendall(message)

    try:
        while True:
            response = s.recv_str_until("eot")
            if response.startswith("okay"):
                break
            s.sendall(message)
        s.close()
        return True
    except:
        print("[CONN] ERROR Other node did not send a response in time!")
        return False


def request_ident():
    print("Requesting identification from all nodes...")
    global all_nodes_listified
    global known_contacts
    for kc in known_contacts:
        send_proto_message("ident\n%s\neot" % self_host, kc)

    while len(all_nodes_listified.splitlines()) < (len(known_contacts)+1):
        pass
    print("Identification received from all nodes!")


def handle_proto_message(sock, client):
    global known_contacts
    global self_host
    received_message = sock.recv_str_until("eot")
    message_parts = received_message.splitlines()

    new_contact = False
    process_report = False
    process_result = False
    send_ident = False
    send_okay = True

    print("Received new message from %s via port %d // message text follows:" % (client[0], client[1]))
    print("-----")
    for s in message_parts:
        print(s)
    print("-----")

    if received_message.startswith("okay"):
        # prevents infinite loops of okay responses
        # realistically should never occur
        send_okay = False

    elif received_message.startswith("hello"):
        if client[0] not in known_contacts and client[0] != self_host:
            known_contacts.append(client[0])
            new_contact = True

    elif received_message.startswith("heartbeat"):
        print("Heard a heartbeat from %s!" % client[0])

    elif received_message.startswith("goodbye"):
        if client[0] in known_contacts:
            known_contacts.remove(client[0])
            save_hosts()

    elif received_message.startswith("contact"):
        for i in range(1, len(message_parts)):
            if message_parts[i] not in known_contacts:
                send_hello(message_parts[i])

    elif received_message.startswith("ident"):
        send_ident = True

    elif received_message.startswith("report"):
        process_report = True

    elif received_message.startswith("result"):
        process_result = True

    elif received_message.startswith("request"):
        job_id = message_parts[1]
        target = message_parts[2]
        requester = message_parts[3]
        current_jobs.append((job_id, target, requester))

    if send_okay:
        sock.sendall("okay\neot")
    sock.close()

    # All below clauses are situational.
    # The node prioritizes acknowledgment before actually acting on the message it received.
    # This is to prevent erroneous timeouts and re-sends.

    if new_contact:
        nodes = ""
        for kc in known_contacts:
            if kc != client[0]:
                nodes += kc + "\n"
        send_proto_message("contact\n%seot" % nodes, client[0])

    if send_ident:
        send_ident_report(message_parts[1])

    if process_report:
        global all_nodes_listified
        print("NEW IDENTITY REPORT: %s via %s // %s // %s" % (client[0], message_parts[1],
                                                              message_parts[2], message_parts[3]))
        ident_report = "<tr>"
        ident_report += "<td>%s</td>" % message_parts[2]
        ident_report += "<td>%s</td>" % client[0]
        ident_report += "<td>%s</td>" % message_parts[1]
        ident_report += "<td>%s</td>" % message_parts[3]
        ident_report += "<td>%s</td>" % message_parts[4]
        ident_report += "<td>%s, %s</td>" % (message_parts[5], message_parts[6])
        ident_report += "</tr>\n"
        all_nodes_listified += ident_report

    if process_result:
        job_id = message_parts[1]
        reported_rtt = float(message_parts[3])
        reported_size = int(message_parts[4])
        reporting_node = client[0]
        res = GeolocResults(reported_rtt, reported_size)
        res.target = message_parts[2]
        res.worker_lat = message_parts[5]
        res.worker_long = message_parts[6]
        res.worker_name = message_parts[7]
        gathered_results[job_id][reporting_node] = res


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

    if path in ["/", "/index.html"]:
        return serve_index()

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
        message += analysis_target + "\n"
        message += self_host + "\n"
        message += "eot"

        for kc in known_contacts:
            send_proto_message(message, kc)

        print("Waiting for results...")
        while len(gathered_results[request_id]) < len(known_contacts)+1:
            pass
        print("All results are in (%d)!" % len(gathered_results[request_id]))
        return serve_analysis(request_id, analysis_target)

    else:
        try:
            with open("web"+path, "rb") as f:
                data = f.read()
                f.close()
            if path.endswith("html") or path.endswith("htm"):
                return HTTPResponse("200 OK", "text/html", data)
            elif path.endswith(".css"):
                return HTTPResponse("200 OK", "text/css", data)
            else:
                return HTTPResponse("404 NOT FOUND", "text/plain", "The specified resource is not here!")
        except:
            return HTTPResponse("404 NOT FOUND", "text/plain", "The specified resource is not here!")


def serve_analysis(request_id, analysis_target):
    global self_host
    print("Attempting to serve analysis page...")
    try:
        print("Trying to read file...")
        with open("web/analysis.html", "rb") as f:
            data = f.read()
            f.close()
        print("File read! Processing results...")
        listified_results = process_results(request_id)
        print("Processed results!")
        print(listified_results)
        datastring = data.decode()
        datastring = datastring.format(hostname=analysis_target,
                                       results=listified_results)
        data = datastring.encode()
        return HTTPResponse("200 OK", "text/html", data)
    except:
        print("File read error!")
        return HTTPResponse("403 FORBIDDEN", "text/plain", "File read error: web/analysis.html")

    return serve_index()


def serve_index():
    global all_nodes_listified
    global known_contacts
    self_city = cloud.city + ", " + cloud.title
    all_nodes_listified = ""
    all_nodes_listified += "<tr>"
    all_nodes_listified += "<td>%s</td>" % cloud.dnsname
    all_nodes_listified += "<td>%s</td>" % self_host
    all_nodes_listified += "<td>%s</td>" % cloud.provider
    all_nodes_listified += "<td>%s</td>" % cloud.zone
    all_nodes_listified += "<td>%s</td>" % self_city
    all_nodes_listified += "<td>%s, %s</td>" % (cloud.coords[0], cloud.coords[1])
    all_nodes_listified += "</tr>\n"
    request_ident()
    try:
        with open("web/form.html", "rb") as f:
            data = f.read()
            f.close()
        print("Finished listifying nodes!")
        num_servers = len(known_contacts) + 1

        data = data.decode()
        data = data.format(currentserver=cloud.dnsname,
                           servercount=num_servers,
                           serverlist=all_nodes_listified)
        data.encode()
        print("Should've finished formatting here!")
        return HTTPResponse("200 OK", "text/html", data)
    except Exception as e:
        print("File read error!")
        print(e)
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

attempt_connection()

if len(known_contacts) == 0:
    itarget = input("Please input the address of a known node, or press enter if this is the first: ")
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
        break
    elif user_input.startswith("count"):
        print("There are currently [%d] nodes in the network." % (len(known_contacts)+1))
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

for so in known_contacts:
    send_proto_message("goodbye\neot", so)
save_hosts()
print("All known contacts notified. Node terminated.")

