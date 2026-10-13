"""Execute the workflow's gate against results from the real disclosure producer."""
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys

import pytest
import yaml

from tests.conftest import envelope_from_dir, seal_json

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize("workflow", [".github/workflows/scpe.yml", "docs/workflows/scpe.yml"])
@pytest.mark.parametrize("require,body,expected", [
    ("true", "", 1),
    ("true", "Assisted-by: codex", 0),
    ("false", "", 0),
])
def test_verify_job_enforces_gate_after_upload(workflow, require, body, expected, tmp_path):
    steps = yaml.safe_load((ROOT / workflow).read_text(encoding="utf-8"))["jobs"]["verify"]["steps"]
    gates = [s for s in steps if s.get("name") == "Enforce verification gate"]
    assert len(gates) == 1, "verify must enforce the result, not merely upload it"
    gate = gates[0]
    upload = next(i for i, s in enumerate(steps) if "actions/upload-artifact@" in s.get("uses", ""))
    assert steps.index(gate) > upload
    assert not gate.get("continue-on-error", False)
    env = dict(os.environ, REQUIRE=require, PR_BODY=body, BASE_SHA="", HEAD_SHA="")
    producer = subprocess.run([sys.executable, str(ROOT / "reference/level1_lint.py")],
                              cwd=tmp_path, env=env, capture_output=True, text=True)
    assert producer.returncode == 0, producer.stderr
    results = json.loads((tmp_path / "results.json").read_text(encoding="utf-8"))
    argv = shlex.split(gate["run"])
    assert argv[0] == "python3"
    proc = subprocess.run([sys.executable, *argv[1:]], cwd=tmp_path,
                          capture_output=True, text=True)
    print(f"{workflow}: require={require} status={results['status']} "
          f"gate_pass={results['gate_pass']} producer_rc={producer.returncode} verify_rc={proc.returncode}")
    assert proc.returncode == expected, proc.stderr


@pytest.mark.parametrize("workflow", [".github/workflows/scpe-seal.yml", "docs/workflows/scpe-seal.yml"])
def test_seal_still_posts_after_gate_failure(workflow):
    seal = yaml.safe_load((ROOT / workflow).read_text(encoding="utf-8"))["jobs"]["seal"]
    assert "github.event.workflow_run.conclusion == 'failure'" in seal["if"]


@pytest.mark.parametrize("name,expected", [("tampered-diff", 1), ("valid-minimal", 0)])
@pytest.mark.parametrize("workflow", [".github/workflows/scpe.yml", "docs/workflows/scpe.yml"])
def test_verify_job_enforces_signed_envelope_result(workflow, name, expected, tmp_path):
    vector = ROOT / "spec/test-vectors" / name
    envelope = envelope_from_dir(vector, tmp_path / "envelope.zip")
    result, rc = seal_json("--envelope", str(envelope), "--keys", str(vector / "keys"),
                           "--require", "true", cwd=tmp_path)
    assert rc == 0, result
    (tmp_path / "results.json").write_text(json.dumps(result), encoding="utf-8")
    steps = yaml.safe_load((ROOT / workflow).read_text(encoding="utf-8"))["jobs"]["verify"]["steps"]
    gate = next(s for s in steps if s.get("name") == "Enforce verification gate")
    argv = shlex.split(gate["run"])
    proc = subprocess.run([sys.executable, *argv[1:]], cwd=tmp_path,
                          capture_output=True, text=True)
    print(f"{workflow}: fixture={name} status={result['status']} "
          f"gate_pass={result['gate_pass']} producer_rc={rc} verify_rc={proc.returncode}")
    assert proc.returncode == expected, proc.stderr
