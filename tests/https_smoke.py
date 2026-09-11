import pathlib
import re
import ssl
import subprocess
import sys
import tempfile
import urllib.parse
import urllib.request


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
        subprocess.run(
            [
                str(binary),
                "put-account",
                str(vault),
                "example.com",
                "yuki@example.com",
                "test-pass",
                "[REDACTED]",
            ],
            cwd=repo,
            check=True,
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
            ctx = ssl._create_unverified_context()
            html = urllib.request.urlopen(url, context=ctx, timeout=5).read().decode()
            assert "<form" in html and "name=\"password\"" in html
            data = urllib.parse.urlencode({"login": "yuki", "password": "test-pass"}).encode()
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
