class HTTPRequest:
    def __init__(self):
        self.method = ""  # GET, POST, PUT, etc. for this request
        self.path = ""    # url path for this request
        self.version = "" # http version for this request
        self.headers = [] # headers from client for this request
        self.length = 0   # length of the request body, if any
        self.body = None  # contents of the request body, if any


class HTTPResponse:
    def __init__(self, code, mime_type=None, body=None):
        self.code = code
        self.mime_type = mime_type
        self.body = body


def get_rtt_to_host(url):
    return


def get_html_of_host(url):
    return


def get_html_file(path):
    return


def parse_url_parts(url):
    parts = []
    url_prot_rem = url.split("://")
    parts.append(url_prot_rem[0])
    url_path_rem = url_prot_rem[1].split("/", 1)
    parts.append(url_path_rem[0])
    parts.append("/"+url_path_rem[1])
    return parts


url = "https://google.com/"
print(parse_url_parts(url))