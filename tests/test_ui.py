"""Exercise the actual loopback boundary and shared policy checker."""
import http.client
import json
from pathlib import Path
import threading
import unittest
from unittest.mock import patch

import agentwatch
from agentwatch_ui import create_server, MAX_FILE_BYTES, MAX_REQUEST_BYTES

ROOT = Path(__file__).resolve().parents[1]


class BrowserTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = create_server(0)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.origin = cls.server.origin

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join()

    def request(self, method='GET', path='/', body=None, headers=None):
        conn = http.client.HTTPConnection('127.0.0.1', self.server.server_port, timeout=5)
        conn.request(method, path, body=body, headers=headers or {})
        response = conn.getresponse()
        result = response.status, dict(response.getheaders()), response.read()
        conn.close()
        return result

    def post(self, payload, **overrides):
        headers = {'Content-Type': 'application/json', 'Origin': self.origin,
                   'X-AgentWatch-Token': self.server.token}
        headers.update(overrides)
        return self.request('POST', '/api/review', json.dumps(payload).encode(), headers)

    def payload(self, text=None):
        return {'events': text if text is not None else (ROOT/'examples/candidate.jsonl').read_text(),
                'domains': ['docs.example.com']}

    def test_assets_and_security_headers(self):
        for path in ('/', '/app.js', '/style.css'):
            status, headers, body = self.request(path=path)
            self.assertEqual(status, 200)
            self.assertTrue(body)
            self.assertEqual(headers['Cache-Control'], 'no-store')
            self.assertIn("frame-ancestors 'none'", headers['Content-Security-Policy'])
            self.assertNotIn('unsafe-inline', headers['Content-Security-Policy'])
            self.assertNotIn('Access-Control-Allow-Origin', headers)
        self.assertIn(self.server.token.encode(), self.request()[2])

    def test_real_upload_matches_cli_and_download_html(self):
        status, _, raw = self.post(self.payload())
        self.assertEqual(status, 200)
        result = json.loads(raw)
        expected = agentwatch.analyze_rules(agentwatch.load(ROOT/'examples/candidate.jsonl'), {'docs.example.com'})
        self.assertEqual(result['report'], expected)
        self.assertEqual(sum(row['review'] for row in expected['sessions']), 3)
        self.assertEqual(result['html'], agentwatch.render(expected))

    def test_cross_origin_host_and_token_are_rejected(self):
        for headers in ({'Origin': 'https://evil.example'}, {'Origin': 'null'},
                        {'Origin': ''}, {'Host': 'evil.example'},
                        {'X-AgentWatch-Token': ''}, {'X-AgentWatch-Token': 'wrong'},
                        {'X-AgentWatch-Token': 'é'},
                        {'Sec-Fetch-Site': 'cross-site'}):
            with self.subTest(headers=headers):
                self.assertEqual(self.post(self.payload(), **headers)[0], 403)
        self.assertEqual(self.request(headers={'Host': 'evil.example'})[0], 403)
        self.assertEqual(self.request(headers={'Sec-Fetch-Site': 'cross-site'})[0], 403)

    def test_no_filesystem_routes_or_preflight(self):
        for path in ('/agentwatch.py', '/../README.md', '/api/review', '/?token=x'):
            self.assertEqual(self.request(path=path)[0], 404)
        self.assertEqual(self.request('OPTIONS', '/api/review')[0], 405)
        self.assertEqual(self.request('POST', '/missing', b'')[0], 404)

    def test_bad_inputs_are_actionable_and_do_not_crash(self):
        for payload in ([], {}, {'events': 1, 'domains': []},
                        self.payload(''), self.payload('{bad'), self.payload('[]'),
                        {'events': '{}', 'domains': ['https://example.com']},
                        {'events': '{}', 'domains': 'example.com'},
                        {'events': '{}', 'domains': [1]},
                        {'events': '{}', 'domains': ['a.com'] * 101}):
            self.assertEqual(self.post(payload)[0], 400)
        duplicate = json.dumps({'event_id': 'a', 'session_id': 'a', 'tool': 'read',
                                'bytes_sent': 0, 'approved': True, 'sensitive': False})
        self.assertEqual(self.post(self.payload(duplicate + '\n' + duplicate))[0], 400)
        self.assertEqual(self.post(self.payload('[' * 15000))[0], 400)
        self.assertEqual(self.request()[0], 200)

    def test_size_and_content_type_limits(self):
        self.assertEqual(self.post(self.payload(' ' * (MAX_FILE_BYTES + 1)))[0], 413)
        self.assertEqual(self.post(self.payload(), **{'Content-Type': 'text/plain'})[0], 415)
        headers = {'Origin': self.origin, 'X-AgentWatch-Token': self.server.token,
                   'Content-Type': 'application/json', 'Content-Length': str(MAX_REQUEST_BYTES + 1)}
        self.assertEqual(self.request('POST', '/api/review', b'', headers)[0], 413)
        headers['Content-Length'] = '-1'
        self.assertEqual(self.request('POST', '/api/review', b'', headers)[0], 400)
        headers['Content-Length'] = '1'
        self.assertEqual(self.request('POST', '/api/review', b'\xff', headers)[0], 400)
        headers['Transfer-Encoding'] = 'chunked'
        self.assertEqual(self.request('POST', '/api/review', b'', headers)[0], 400)

    def test_untrusted_strings_are_escaped_in_export(self):
        event = {'event_id': '<img src=x onerror=alert(1)>', 'session_id': '<script>alert(1)</script>',
                 'tool': 'shell', 'bytes_sent': 0, 'approved': False, 'sensitive': False}
        status, _, raw = self.post(self.payload(json.dumps(event)))
        self.assertEqual(status, 200)
        html = json.loads(raw)['html']
        self.assertNotIn('<script>', html)
        self.assertNotIn('<img', html)
        self.assertIn('&lt;script&gt;', html)

    def test_empty_allowlist_flags_network_and_no_server_persistence(self):
        payload = self.payload()
        payload['domains'] = []
        with patch('agentwatch.write_reports', side_effect=AssertionError('must not persist')):
            status, _, raw = self.post(payload)
        self.assertEqual(status, 200)
        self.assertGreater(sum(r['review'] for r in json.loads(raw)['report']['sessions']), 3)
        self.assertEqual(self.request(path='/report.json')[0], 404)

    def test_busy_review_and_internal_error(self):
        with self.server.review_lock:
            self.assertEqual(self.post(self.payload())[0], 429)
        with patch('agentwatch_ui.analyze_rules', side_effect=RuntimeError('SECRET')):
            status, _, body = self.post(self.payload())
        self.assertEqual(status, 500)
        self.assertNotIn(b'SECRET', body)

    def test_truncated_upload_is_rejected(self):
        import socket
        request = (f'POST /api/review HTTP/1.1\r\nHost: {self.server.expected_host}\r\n'
                   f'Origin: {self.origin}\r\nX-AgentWatch-Token: {self.server.token}\r\n'
                   'Content-Type: application/json\r\nContent-Length: 100\r\n\r\n{}')
        with socket.create_connection(('127.0.0.1', self.server.server_port), timeout=5) as sock:
            sock.sendall(request.encode())
            sock.shutdown(socket.SHUT_WR)
            self.assertIn(b'400', sock.recv(1024).split(b'\r\n')[0])

    def test_session_limit_and_unicode_upload(self):
        events = [json.dumps({'event_id': str(i), 'session_id': str(i), 'tool': 'read',
                             'bytes_sent': 0, 'approved': True, 'sensitive': False}) for i in range(2001)]
        self.assertEqual(self.post(self.payload('\n'.join(events)))[0], 400)
        self.assertEqual(self.post(self.payload('\ud800'))[0], 400)

    def test_malformed_envelope_and_unsupported_method(self):
        headers = {'Content-Type': 'application/json', 'Origin': self.origin,
                   'X-AgentWatch-Token': self.server.token}
        self.assertEqual(self.request('POST', '/api/review', b'{', headers)[0], 400)
        self.assertEqual(self.request('DELETE', '/')[0], 501)


class LaunchTests(unittest.TestCase):
    def test_version_and_port_validation(self):
        from agentwatch_ui import main
        for args, code in [(['--version'], 0), (['--port', '-1'], 2), (['--port', '65536'], 2)]:
            with self.subTest(args=args), self.assertRaises(SystemExit) as error:
                main(args)
            self.assertEqual(error.exception.code, code)

    def test_start_open_stop_and_bind_error(self):
        from agentwatch_ui import main
        from unittest.mock import MagicMock
        server = MagicMock()
        server.origin = 'http://127.0.0.1:1234'
        server.serve_forever.side_effect = KeyboardInterrupt
        with patch('agentwatch_ui.create_server', return_value=server), patch('agentwatch_ui.webbrowser.open') as opened:
            self.assertEqual(main(['--open']), 0)
            opened.assert_called_once_with(server.origin)
            server.__exit__.assert_called_once()
        with patch('agentwatch_ui.create_server', side_effect=OSError), self.assertRaises(SystemExit) as error:
            main([])
        self.assertEqual(error.exception.code, 2)


if __name__ == '__main__':
    unittest.main()
