import socket
import socketutil
import time


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


target_url = "http://google.com/"
url_parts = parse_url_parts(target_url)
print(url_parts)
print()

demo = HTTPRequest()
demo.method = "HEAD"
demo.path = url_parts[2]
demo.version = "HTTP/1.1"

if url_parts[0] == "https":
    port = 443
else:
    port = 80

send_http_request(demo, url_parts[1], port)



