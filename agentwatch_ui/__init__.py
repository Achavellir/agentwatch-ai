"""Single-user loopback UI. No remote service, filesystem API or log persistence."""
import argparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib.resources import files
import json
import secrets
import threading
import webbrowser

from agentwatch import __version__, analyze_rules, load_bytes, normalize_domain, render

MAX_FILE_BYTES = 2_000_000
MAX_REQUEST_BYTES = 12_010_000  # JSON escaping can expand a file up to sixfold.
CSP = "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'; object-src 'none'"


class LocalServer(ThreadingHTTPServer):
    daemon_threads = True
    block_on_close = True

    def __init__(self, port):
        self.token = secrets.token_urlsafe(32)
        self.review_lock = threading.Lock()
        self.slots = threading.BoundedSemaphore(8)
        super().__init__(('127.0.0.1', port), Handler)
        self.origin = f'http://127.0.0.1:{self.server_port}'
        self.expected_host = f'127.0.0.1:{self.server_port}'

    def process_request(self, request, client_address):
        if not self.slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self.slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self.slots.release()

    def handle_error(self, request, client_address):
        # Do not print request contents, tokens, paths or stack traces.
        pass


class Handler(BaseHTTPRequestHandler):
    server_version = 'AgentWatchLocal'
    sys_version = ''

    def setup(self):
        super().setup()
        self.connection.settimeout(10)

    def log_message(self, *args):
        pass

    def send_body(self, status, body, mime='application/json; charset=utf-8'):
        if isinstance(body, dict):
            body = json.dumps(body, allow_nan=False).encode('utf-8')
        elif isinstance(body, str):
            body = body.encode('utf-8')
        self.send_response(status)
        self.send_header('Content-Type', mime)
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('Content-Security-Policy', CSP)
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('X-Frame-Options', 'DENY')
        self.send_header('Referrer-Policy', 'no-referrer')
        self.send_header('Connection', 'close')
        self.end_headers()
        self.close_connection = True
        self.wfile.write(body)

    def send_error(self, code, message=None, explain=None):
        self.send_body(code, {'error': 'Unsupported request.'})

    def local_request(self):
        return (self.headers.get_all('Host') == [self.server.expected_host]
                and self.headers.get('Sec-Fetch-Site', 'none') in ('none', 'same-origin'))

    def do_GET(self):
        if not self.local_request():
            self.send_body(403, {'error': 'Open the local address printed in Terminal.'})
            return
        assets = {'/': ('index.html', 'text/html'), '/app.js': ('app.js', 'text/javascript'),
                  '/style.css': ('style.css', 'text/css')}
        if self.path not in assets:
            self.send_body(404, {'error': 'Page not found.'})
            return
        name, mime = assets[self.path]
        body = files('agentwatch_ui').joinpath(name).read_text(encoding='utf-8')
        if name == 'index.html':
            body = body.replace('__TOKEN__', self.server.token)
        self.send_body(200, body, mime + '; charset=utf-8')

    def do_OPTIONS(self):
        self.send_body(405, {'error': 'Cross-origin access is not supported.'})

    def do_POST(self):
        if self.path != '/api/review':
            self.send_body(404, {'error': 'Page not found.'})
            return
        tokens = self.headers.get_all('X-AgentWatch-Token', [])
        if (not self.local_request() or self.headers.get_all('Origin') != [self.server.origin]
                or len(tokens) != 1 or not secrets.compare_digest(tokens[0].encode('utf-8'), self.server.token.encode('ascii'))):
            self.send_body(403, {'error': 'Request denied. Reload the local page and try again.'})
            return
        if self.headers.get('Content-Type') != 'application/json':
            self.send_body(415, {'error': 'Expected a JSON upload.'})
            return
        lengths = self.headers.get_all('Content-Length', [])
        if self.headers.get('Transfer-Encoding') or len(lengths) != 1 or not lengths[0].isascii() or not lengths[0].isdigit():
            self.send_body(400, {'error': 'A valid Content-Length is required.'})
            return
        # Avoid int conversion of unbounded digit strings.
        if len(lengths[0]) > 8 or int(lengths[0]) > MAX_REQUEST_BYTES:
            self.send_body(413, {'error': 'Upload is too large. Choose a file of 2 MB or less.'})
            return
        if not self.server.review_lock.acquire(blocking=False):
            self.send_body(429, {'error': 'Another review is running. Try again shortly.'})
            return
        try:
            length = int(lengths[0])
            raw = self.rfile.read(length)
            if len(raw) != length:
                raise ValueError('Upload was incomplete. Please try again.')
            data = json.loads(raw.decode('utf-8'))
            if not isinstance(data, dict) or set(data) != {'events', 'domains'}:
                raise ValueError('Choose an activity file and supply an approved website list.')
            if not isinstance(data['events'], str) or not isinstance(data['domains'], list):
                raise ValueError('Invalid activity file or website list.')
            if len(data['domains']) > 100 or any(not isinstance(d, str) for d in data['domains']):
                raise ValueError('Use at most 100 exact website hostnames.')
            encoded = data['events'].encode('utf-8')
            if len(encoded) > MAX_FILE_BYTES:
                self.send_body(413, {'error': 'Choose an activity file of 2 MB or less.'})
                return
            domains = {normalize_domain(d) for d in data['domains']}
            candidate = load_bytes(encoded)
            if len(candidate) > 2000 or sum(map(len, candidate.values())) > 20000:
                raise ValueError('Use at most 2,000 sessions and 20,000 events per browser review.')
            report = analyze_rules(candidate, domains)
            result = {'report': report, 'html': render(report)}
        except UnicodeError:
            self.send_body(400, {'error': 'Use a UTF-8 JSONL activity file.'})
        except json.JSONDecodeError:
            self.send_body(400, {'error': 'Upload is not valid JSON.'})
        except RecursionError:
            self.send_body(400, {'error': 'Input nesting is too deep.'})
        except ValueError as error:
            self.send_body(400, {'error': str(error)})
        except TimeoutError:
            self.send_body(408, {'error': 'Upload timed out. Try again.'})
        except Exception:
            self.send_body(500, {'error': 'Review could not finish. Try a smaller file or restart AgentWatch.'})
        else:
            self.send_body(200, result)
        finally:
            self.server.review_lock.release()


def create_server(port=0):
    return LocalServer(port)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--version', action='version', version=f'AgentWatch UI {__version__}')
    parser.add_argument('--port', type=int, default=0, help='Local port; default chooses an available port')
    parser.add_argument('--open', action='store_true', help='Open the page in your default browser')
    args = parser.parse_args(argv)
    if not 0 <= args.port <= 65535:
        parser.error('port must be between 0 and 65535')
    try:
        server = create_server(args.port)
    except OSError:
        parser.exit(2, 'Could not start the local server. Try another port.\n')
    with server:
        print(f'AgentWatch local review: {server.origin}\nPress Ctrl+C to stop. No uploads are saved by the server.', flush=True)
        if args.open:
            webbrowser.open(server.origin)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass
    return 0
