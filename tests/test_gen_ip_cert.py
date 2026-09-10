import pathlib
import stat
import subprocess
import tempfile


def main() -> int:
    repo = pathlib.Path(__file__).resolve().parents[1]
    script = repo / "scripts" / "gen-ip-cert.sh"
    with tempfile.TemporaryDirectory() as tmp:
        out = pathlib.Path(tmp) / "certs"
        result = subprocess.run(
            [str(script), "127.0.0.1", str(out), "1"],
            cwd=repo,
            check=True,
            text=True,
            stdout=subprocess.PIPE,
        )
        cert = out / "alfie-ip-cert.pem"
        key = out / "alfie-ip-key.pem"
        assert cert.exists()
        assert key.exists()
        assert stat.S_IMODE(key.stat().st_mode) == 0o600
        text = subprocess.run(
            ["openssl", "x509", "-in", str(cert), "-noout", "-text"],
            check=True,
            text=True,
            stdout=subprocess.PIPE,
        ).stdout
        assert "IP Address:127.0.0.1" in text
        assert "TLS Web Server Authentication" in text
        assert "certificate:" in result.stdout
        assert "private_key:" in result.stdout
    print("gen_ip_cert: ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
