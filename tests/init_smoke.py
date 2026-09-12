"""End-to-end first-time setup over the one-off HTTPS certificate."""

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
    port = "18465"

    with tempfile.TemporaryDirectory() as tmp:
        tmpdir = pathlib.Path(tmp)
        vault = tmpdir / "vault"
        out = tmpdir / "out"

        server = subprocess.Popen(
            [str(binary), "serve-init-tls", str(vault), "127.0.0.1", "127.0.0.1", port, str(out)],
            cwd=repo,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        banner = ""
        url = None
        fingerprint = None
        try:
            for _ in range(40):
                line = server.stdout.readline()
                if not line:
                    break
                banner += line
                if line.startswith("  SHA-256: "):
                    fingerprint = line.split("SHA-256: ", 1)[1].strip()
                match = re.match(r"setup link: (https://127\.0\.0\.1:%s/init/[0-9a-f]+)$" % port,
                                 line.strip())
                if match:
                    url = match.group(1)
                    break
            assert url, banner
            assert fingerprint, banner
            assert "FIRST-TIME VAULT SETUP" in banner, banner

            ctx = ssl._create_unverified_context()
            page = urllib.request.urlopen(url, context=ctx, timeout=10).read().decode()
            # Red, unmistakable, and echoing the fingerprint printed on the terminal.
            assert "#450a0a" in page
            assert "FIRST-TIME VAULT SETUP" in page
            assert "exactly once" in page
            assert fingerprint in page, "page must echo the terminal fingerprint"

            data = urllib.parse.urlencode(
                {"login": "yuki", "password": "Correct-Horse-9", "confirm": "Correct-Horse-9"}
            ).encode()
            body = urllib.request.urlopen(
                urllib.request.Request(url, data=data, method="POST"), context=ctx, timeout=30
            ).read().decode()
            assert "Vault created" in body
            assert "Correct-Horse-9" not in body
        finally:
            try:
                server.wait(timeout=30)
            except subprocess.TimeoutExpired:
                server.kill()
                server.wait(timeout=10)

        # The setup server exits on its own once the vault exists.
        assert server.returncode is not None

        assert (vault / "vault.meta").exists()
        ca_cert = out / "alfie-local-ca-cert.pem"
        assert ca_cert.exists()
        assert "CERTIFICATE" in ca_cert.read_text()

        # No CA private key anywhere on disk; only the server key, and only at 0600.
        for path in out.rglob("*"):
            if not path.is_file():
                continue
            if "PRIVATE KEY" in path.read_text(errors="ignore"):
                assert path.name == "alfie-ip-key.pem", f"unexpected private key at {path}"
                assert oct(path.stat().st_mode)[-3:] == "600"

        # Running setup again against a live vault must refuse before serving anything.
        again = subprocess.run(
            [str(binary), "serve-init-tls", str(vault), "127.0.0.1", "127.0.0.1", port, str(out)],
            cwd=repo,
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert again.returncode == 1, again.stdout
        assert "already initialized" in again.stderr
        assert "/init/" not in again.stdout

    print("init_smoke: ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
