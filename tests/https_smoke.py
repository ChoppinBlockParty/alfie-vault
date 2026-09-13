import pathlib
import re
import socket
import ssl
import subprocess
import sys
import tempfile
import time
import urllib.parse
import urllib.request


def connect_tls(context, timeout=5):
    """Open a fixture connection with a bounded client-side wait."""
    connection = socket.create_connection(("127.0.0.1", 18443), timeout=timeout)
    return context.wrap_socket(connection, server_hostname="localhost")


def test_malformed_requests(context, server):
    """Invalid framing must close only the offending connection."""
    malformed = [
        b"POST / HTTP/1.1\r\nContent-Length: nope\r\n\r\n",
        b"POST / HTTP/1.1\r\nContent-Length: -1\r\n\r\n",
        b"POST / HTTP/1.1\r\nContent-Length: 999999999999999999999999\r\n\r\n",
        b"POST / HTTP/1.1\r\nContent-Length: 1048576\r\n\r\n",
        b"POST / HTTP/1.1\r\nContent-Length: 0\r\nContent-Length: 1\r\n\r\n",
        b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n",
        b"GET / HTTP/1.1\r\nX: " + b"x" * 17000,
    ]
    for payload in malformed:
        with connect_tls(context) as peer:
            try:
                peer.sendall(payload)
                assert peer.recv(1024) == b"", "malformed request accepted"
            except (ssl.SSLError, ConnectionResetError, BrokenPipeError):
                pass  # TLS errors and connection resets are valid rejection paths.
        assert server.poll() is None, "malformed request killed server"


def test_abrupt_disconnects(context, target):
    """Disconnects during handshake and response must not cause fatal SIGPIPE."""
    with socket.create_connection(("127.0.0.1", 18443), timeout=5) as peer:
        peer.sendall(b"not TLS")
    for _ in range(3):
        with connect_tls(context) as peer:
            peer.sendall(f"GET {target} HTTP/1.1\r\nHost: localhost\r\n\r\n".encode())


def assert_deadline_closes(peer):
    """Allow scheduling tolerance around the server's 10-second deadline."""
    started = time.monotonic()
    assert peer.recv(1) == b""
    assert 8 <= time.monotonic() - started < 14


def test_connection_deadlines(context):
    """Both an absent TLS handshake and an incomplete HTTP body must time out."""
    with socket.create_connection(("127.0.0.1", 18443), timeout=15) as peer:
        assert_deadline_closes(peer)
    with connect_tls(context, timeout=15) as peer:
        peer.sendall(b"POST / HTTP/1.1\r\nContent-Length: 10\r\n\r\nx")
        assert_deadline_closes(peer)


def main() -> int:
    repo = pathlib.Path(__file__).resolve().parents[1]
    binary = pathlib.Path(sys.argv[1])
    with tempfile.TemporaryDirectory() as tmp:
        tmpdir = pathlib.Path(tmp)
        cert = tmpdir / "cert.pem"
        key = tmpdir / "key.pem"
        vault = tmpdir / "vault"
        subprocess.run(
            [
                "openssl",
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-keyout",
                str(key),
                "-out",
                str(cert),
                "-days",
                "1",
                "-nodes",
                "-subj",
                "/CN=localhost",
            ],
            cwd=repo,
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        # Secrets go in on stdin; argv is visible process-wide.
        subprocess.run(
            [str(binary), "init-vault", str(vault), "yuki"],
            cwd=repo,
            check=True,
            input=b"test-passphrase\n",
            stdout=subprocess.DEVNULL,
        )
        subprocess.run(
            [
                str(binary),
                "put-account",
                str(vault),
                "example.com",
                "yuki@example.com",
            ],
            cwd=repo,
            check=True,
            input=b'test-passphrase\n{"secret":"[REDACTED]"}\n',
            stdout=subprocess.DEVNULL,
        )
        server = subprocess.Popen(
            [
                str(binary),
                "serve-unlock-tls",
                str(vault),
                "yuki",
                "127.0.0.1",
                "18443",
                str(cert),
                str(key),
                "account",
                "example.com",
                "yuki@example.com",
                "fill_password",
            ],
            cwd=repo,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        try:
            line = server.stdout.readline().strip()
            match = re.match(r"unlock link: (https://127\.0\.0\.1:18443/unlock/[0-9a-f]+)$", line)
            assert match, line
            url = match.group(1)
            code_line = server.stdout.readline().strip()
            code_match = re.fullmatch(r"Request code: ([0-9]{6})", code_line)
            assert code_match, code_line
            ctx = ssl._create_unverified_context()
            test_malformed_requests(ctx, server)
            test_abrupt_disconnects(ctx, urllib.parse.urlsplit(url).path)
            test_connection_deadlines(ctx)

            # A valid human unlock must still succeed after all hostile connections.
            html = urllib.request.urlopen(url, context=ctx, timeout=5).read().decode()
            assert code_match.group(1) in html
            assert "<form" in html and "name=\"password\"" in html
            data = urllib.parse.urlencode({"login": "yuki", "password": "test-passphrase"}).encode()
            request = urllib.request.Request(url, data=data, method="POST")
            body = urllib.request.urlopen(request, context=ctx, timeout=5).read().decode()
            assert "Unlocked" in body
            assert "[REDACTED]" not in body
        finally:
            try:
                server.wait(timeout=5)
            except subprocess.TimeoutExpired:
                server.kill()
                server.wait(timeout=5)
    print("https_smoke: ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
