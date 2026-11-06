"""Signed evidence: XRAY results as in-toto attestations, signed with an SSH key.

An attestation is an in-toto Statement (the format SLSA and Sigstore use):
the subjects are files named with their SHA-256, and the predicate is an
XRAY result about them: a capability contract, a capability profile, a
drift or compare report, or the head of a capability log. The Statement is
written as canonical JSON and signed with ``ssh-keygen -Y sign`` (an SSH
signature, the same mechanism git uses for signed commits), in the
namespace ``xray-attestation``. Anyone with the signer's public key in an
allowed-signers file can check it with ``xray attest verify``, which also
re-hashes every subject still present on disk.

If cosign is installed, ``--cosign`` also signs the Statement with
Sigstore's keyless flow.
"""

from __future__ import annotations

import datetime
import hashlib
import json
import os
import shutil
import subprocess
from pathlib import Path

from . import __version__

STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
PREDICATE_BASE = "https://github.com/luciusthorne/xray/attestation"
NAMESPACE = "xray-attestation"


class AttestError(RuntimeError):
    pass


def default_key():
    base = os.environ.get("XDG_CONFIG_HOME") or str(Path.home() / ".config")
    return Path(base) / "xray" / "attest_ed25519"


def sha256(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def subject(path, name=None):
    return {"name": name or str(path), "digest": {"sha256": sha256(path)}}


def statement(kind, subjects, predicate):
    return {
        "_type": STATEMENT_TYPE,
        "subject": subjects,
        "predicateType": f"{PREDICATE_BASE}/{kind}/v1",
        "predicate": {
            **predicate,
            "producer": {"name": "xray", "version": __version__},
            "created": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
        },
    }


def canonical(data):
    return (json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode()


def contract_statement(contract_path):
    from .contract import load_contract

    contract = load_contract(contract_path)
    subjects = [subject(contract_path, Path(contract_path).name)]
    if Path(contract.program).is_file():
        subjects.append(subject(contract.program))
    return statement("contract", subjects, {
        "program": contract.program,
        "program_sha256_in_contract": contract.sha256,
        "contract": Path(contract_path).read_text(encoding="utf-8"),
    })


def profile_statement(paths):
    from .profile import profile

    subjects, profiles = [], {}
    for path in paths:
        subjects.append(subject(path))
        profiles[str(path)] = profile(path)
    return statement("profile", subjects, {"profiles": profiles})


def report_statement(report_path, inputs):
    data = json.loads(Path(report_path).read_text(encoding="utf-8"))
    subjects = [subject(path) for path in inputs] + [subject(report_path, Path(report_path).name)]
    return statement("report", subjects, {"report": data})


def log_statement(log_path):
    from . import caplog

    entries = caplog.read_log(log_path)
    ok, head, message = caplog.verify(entries)
    if not ok:
        raise AttestError(f"the log does not verify: {message}")
    return statement("log-head", [subject(log_path, Path(log_path).name)], {
        "entries": len(entries), "head": head,
        "packages": len({entry.get("package") for entry in entries}),
    })


def keygen(path=None):
    path = Path(path or default_key())
    if path.exists():
        raise AttestError(f"{path} already exists")
    path.parent.mkdir(parents=True, exist_ok=True)
    done = subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "xray attestation key", "-f", str(path)],
                          capture_output=True, text=True, check=False)
    if done.returncode != 0:
        raise AttestError(done.stderr.strip() or "ssh-keygen failed")
    return path


def sign(statement_data, out_path, key=None, identity="xray", cosign=False):
    """Write the Statement, its SSH signature (.sig) and, with cosign, a Sigstore bundle."""

    if shutil.which("ssh-keygen") is None:
        raise AttestError("ssh-keygen (OpenSSH) is needed to sign")
    key = Path(key or default_key())
    if not key.exists():
        raise AttestError(f"no signing key at {key}: create one with `xray attest keygen`")
    out_path = Path(out_path)
    out_path.write_bytes(canonical(statement_data))
    signature = Path(f"{out_path}.sig")
    signature.unlink(missing_ok=True)
    done = subprocess.run(["ssh-keygen", "-Y", "sign", "-q", "-n", NAMESPACE, "-f", str(key), str(out_path)],
                          capture_output=True, text=True, check=False)
    if done.returncode != 0:
        raise AttestError(done.stderr.strip() or "ssh-keygen -Y sign failed")
    public = Path(f"{key}.pub").read_text().split()
    signers = Path(f"{out_path}.signers")
    signers.write_text(f'{identity} namespaces="{NAMESPACE}" {public[0]} {public[1]}\n')
    written = [out_path, signature, signers]
    if cosign:
        if shutil.which("cosign") is None:
            raise AttestError("cosign is not installed")
        bundle = Path(f"{out_path}.sigstore.json")
        done = subprocess.run(["cosign", "sign-blob", "--yes", "--bundle", str(bundle), str(out_path)],
                              capture_output=True, text=True, check=False)
        if done.returncode != 0:
            raise AttestError(done.stderr.strip()[-300:] or "cosign sign-blob failed")
        written.append(bundle)
    return written


def verify(statement_path, signers, identity="xray", check_subjects=True):
    """Return (ok, messages). Checks the SSH signature and the subjects' current SHA-256."""

    statement_path = Path(statement_path)
    signature = Path(f"{statement_path}.sig")
    if not signature.exists():
        return False, [f"no signature file {signature}"]
    with open(statement_path, "rb") as handle:
        done = subprocess.run(["ssh-keygen", "-Y", "verify", "-f", str(signers), "-I", identity, "-n", NAMESPACE,
                               "-s", str(signature)], stdin=handle, capture_output=True, text=True, check=False)
    messages = [(done.stdout or done.stderr).strip()]
    ok = done.returncode == 0
    if ok and check_subjects:
        data = json.loads(statement_path.read_text(encoding="utf-8"))
        base = statement_path.parent
        for item in data.get("subject", []):
            candidates = [Path(item["name"]), base / Path(item["name"]).name]
            path = next((candidate for candidate in candidates if candidate.is_file()), None)
            if path is None:
                messages.append(f"subject not on disk, not re-hashed: {item['name']}")
            elif sha256(path) != item["digest"]["sha256"]:
                ok = False
                messages.append(f"CHANGED since it was attested: {item['name']}")
            else:
                messages.append(f"unchanged: {item['name']}")
    return ok, messages
