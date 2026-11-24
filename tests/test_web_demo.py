import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from scripts.web_demo import run_demo, fetch_public_page, CountedHTTPS, MAX_RESPONSE


class WebDemoTests(unittest.TestCase):
    def test_one_observation_two_policies_and_private_outputs(self):
        with tempfile.TemporaryDirectory() as root:
            out = Path(root) / 'run'
            with patch('scripts.web_demo.fetch_public_page', return_value={'status': 200, 'request_bytes': 123, 'response_bytes': 456}) as fetch:
                run_demo(out)
            fetch.assert_called_once_with()
            event = json.loads((out / 'activity.jsonl').read_text())
            self.assertEqual(event['bytes_sent'], 123)
            self.assertEqual(event['destination'], 'https://www.python.org')
            self.assertEqual((out / 'activity.jsonl').stat().st_mode & 0o777, 0o600)
            self.assertEqual(out.stat().st_mode & 0o777, 0o700)
            allowed = json.loads((out / 'approved/report.json').read_text())
            other = json.loads((out / 'unapproved/report.json').read_text())
            self.assertFalse(allowed['sessions'][0]['review'])
            self.assertTrue(other['sessions'][0]['review'])
            self.assertEqual(other['sessions'][0]['findings'][0]['rules'], ['UNAPPROVED_DESTINATION'])
            self.assertTrue((out / 'COMPLETE').exists())

    def test_existing_directory_rejected_before_network(self):
        with tempfile.TemporaryDirectory() as root, patch('scripts.web_demo.fetch_public_page') as fetch:
            with self.assertRaises(FileExistsError):
                run_demo(Path(root))
            fetch.assert_not_called()

    def test_network_failure_never_produces_success_marker(self):
        with tempfile.TemporaryDirectory() as root, patch('scripts.web_demo.fetch_public_page', side_effect=OSError('offline')):
            out = Path(root) / 'run'
            with self.assertRaises(OSError):
                run_demo(out)
            self.assertFalse((out / 'COMPLETE').exists())

    def test_redirect_not_followed_and_response_not_read(self):
        with patch('scripts.web_demo.CountedHTTPS') as cls:
            conn = cls.return_value
            conn.getresponse.return_value.status = 302
            with self.assertRaises(ValueError):
                fetch_public_page()
            conn.request.assert_called_once()
            conn.getresponse.return_value.read.assert_not_called()
            conn.close.assert_called_once()

    def test_response_limit_and_cleanup(self):
        with patch('scripts.web_demo.CountedHTTPS') as cls:
            conn = cls.return_value
            conn.getresponse.return_value.status = 200
            conn.getresponse.return_value.read.return_value = b'x' * (MAX_RESPONSE + 1)
            with self.assertRaises(ValueError):
                fetch_public_page()
            conn.getresponse.return_value.read.assert_called_once_with(MAX_RESPONSE + 1)
            conn.close.assert_called_once()

    def test_count_http_bytes_not_response_or_tls_bytes(self):
        with patch('http.client.HTTPSConnection.send') as send:
            conn = CountedHTTPS('www.python.org')
            conn.send(b'GET / HTTP/1.1\r\n')
            self.assertEqual(conn.request_bytes, 16)
            send.side_effect = OSError('failed send')
            with self.assertRaises(OSError):
                conn.send(b'abc')
            self.assertEqual(conn.request_bytes, 16)
