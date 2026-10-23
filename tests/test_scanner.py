import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from scanner import scan  # noqa: E402
from app import app  # noqa: E402

BAD = (ROOT / "samples" / "insecure.tf").read_text()
GOOD = (ROOT / "samples" / "secure.tf").read_text()


def rules(code):
    return {f["rule"] for f in scan(code)["findings"]}


def test_public_s3_bucket_detected():
    assert "CG001" in rules(BAD)


def test_open_ssh_port_detected():
    assert "CG002" in rules(BAD)


def test_open_non_web_port_detected():
    assert "CG003" in rules(BAD)


def test_unencrypted_ebs_detected():
    assert "CG004" in rules(BAD)


def test_rds_unencrypted_and_public_detected():
    r = rules(BAD)
    assert "CG005" in r and "CG006" in r


def test_wildcard_iam_detected():
    assert "CG007" in rules(BAD)


def test_hardcoded_password_detected():
    assert "CG008" in rules(BAD)


def test_secure_sample_is_clean():
    result = scan(GOOD)
    assert result["findings"] == []
    assert result["score"] == 100 and result["grade"] == "A"


def test_insecure_sample_fails():
    result = scan(BAD)
    assert result["grade"] == "F"
    assert result["counts"]["HIGH"] >= 7


def test_web_and_api_endpoints():
    client = app.test_client()
    assert client.get("/health").get_json() == {"status": "ok"}
    assert client.get("/").status_code == 200
    data = client.post("/api/scan", data=BAD).get_json()
    assert data["score"] < 50
