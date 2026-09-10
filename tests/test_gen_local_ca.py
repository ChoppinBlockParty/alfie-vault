import pathlib
import stat
import subprocess
import tempfile


def main() -> int:
    repo = pathlib.Path(__file__).resolve().parents[1]
    script = repo / "scripts" / "gen-local-ca.sh"
    with tempfile.TemporaryDirectory() as tmp:
        out = pathlib.Path(tmp) / "ca"
        result = subprocess.run(
            [str(script), str(out), "Alfie Local Test CA", "30"],
            cwd=repo,
            check=True,
            text=True,
            stdout=subprocess.PIPE,
        )
        ca_cert = out / "alfie-local-ca-cert.pem"
        ca_key = out / "alfie-local-ca-key.pem"
        assert ca_cert.exists()
        assert ca_key.exists()
        assert stat.S_IMODE(out.stat().st_mode) == 0o700
        assert stat.S_IMODE(ca_key.stat().st_mode) == 0o600
        text = subprocess.run(
            ["openssl", "x509", "-in", str(ca_cert), "-noout", "-text"],
            check=True,
            text=True,
            stdout=subprocess.PIPE,
        ).stdout
        assert "CA:TRUE" in text
        assert "Certificate Sign" in text
        assert "Alfie Local Test CA" in text
        assert "ca_certificate:" in result.stdout
        assert "ca_private_key:" in result.stdout
    print("gen_local_ca: ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
