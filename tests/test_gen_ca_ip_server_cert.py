import pathlib
import stat
import subprocess
import tempfile


def main() -> int:
    repo = pathlib.Path(__file__).resolve().parents[1]
    ca_script = repo / "scripts" / "gen-local-ca.sh"
    server_script = repo / "scripts" / "gen-ca-ip-server-cert.sh"
    with tempfile.TemporaryDirectory() as tmp:
        ca_dir = pathlib.Path(tmp) / "ca"
        server_dir = pathlib.Path(tmp) / "server"
        subprocess.run([str(ca_script), str(ca_dir), "Alfie Local Test CA", "30"], check=True)
        result = subprocess.run(
            [
                str(server_script),
                "127.0.0.1",
                str(server_dir),
                str(ca_dir / "alfie-local-ca-cert.pem"),
                str(ca_dir / "alfie-local-ca-key.pem"),
                "30",
            ],
            cwd=repo,
            check=True,
            text=True,
            stdout=subprocess.PIPE,
        )
        cert = server_dir / "alfie-ip-cert.pem"
        key = server_dir / "alfie-ip-key.pem"
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
        assert "CA:FALSE" in text
        verify = subprocess.run(
            ["openssl", "verify", "-CAfile", str(ca_dir / "alfie-local-ca-cert.pem"), str(cert)],
            check=True,
            text=True,
            stdout=subprocess.PIPE,
        ).stdout
        assert ": OK" in verify
        assert "certificate:" in result.stdout
        assert "private_key:" in result.stdout
    print("gen_ca_ip_server_cert: ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
