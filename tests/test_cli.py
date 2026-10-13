import hashlib
import json
import subprocess
import sys
from pathlib import Path

import pytest
from typer.testing import CliRunner

from js_forensics import __version__
from js_forensics.cli import app

from .conftest import FIXTURES

runner = CliRunner()


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


@pytest.fixture
def sample(tmp_path: Path) -> Path:
    path = tmp_path / "sample.js"
    path.write_bytes((FIXTURES / "obfuscated_sample.js").read_bytes())
    return path


def test_version():
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert result.stdout.strip() == f"js-forensics {__version__}"
    assert __version__ == "0.1.0"


def test_help_lists_every_command():
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    for command in ("analyze", "strings", "endpoints", "deobfuscate", "report"):
        assert command in result.stdout
    assert "never executed" in result.stdout


@pytest.mark.parametrize("command", ["analyze", "strings", "endpoints", "deobfuscate", "report"])
def test_command_help(command):
    result = runner.invoke(app, [command, "--help"])
    assert result.exit_code == 0
    assert "Example: js-forensics " + command in result.stdout


def test_analyze_text(sample: Path):
    before = sha256(sample)
    result = runner.invoke(app, ["analyze", str(sample)])
    assert result.exit_code == 0
    assert "Obfuscation indicators (heuristic score" in result.stdout
    assert "Escape-encoded string literals" in result.stdout
    assert "Potential network endpoints" in result.stdout
    assert sha256(sample) == before


def test_analyze_json_to_file(sample: Path, tmp_path: Path):
    output = tmp_path / "report.json"
    result = runner.invoke(
        app, ["analyze", str(sample), "--format", "json", "--output", str(output)]
    )
    assert result.exit_code == 0
    report = json.loads(output.read_text())
    assert report["schema_version"] == "1.0"
    assert report["file"]["path"] == str(sample)
    assert report["file"]["sha256"] == sha256(sample)
    assert report["obfuscation"]["score"] > 0
    assert result.stdout == ""  # the notice goes to stderr


def test_analyze_text_to_file(sample: Path, tmp_path: Path):
    output = tmp_path / "summary.txt"
    result = runner.invoke(app, ["analyze", str(sample), "-o", str(output)])
    assert result.exit_code == 0
    assert "Browser APIs referenced" in output.read_text()


def test_strings_command(sample: Path):
    result = runner.invoke(app, ["strings", str(sample), "--format", "json"])
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    values = {string["value"]: string["category"] for string in payload["strings"]}
    assert values["https://api.example.com"] == "url"
    assert values["done"] == "other"

    filtered = runner.invoke(app, ["strings", str(sample), "--category", "url"])
    assert filtered.exit_code == 0
    assert "https://api.example.com" in filtered.stdout
    assert "done" not in filtered.stdout
    assert "1 distinct string(s)." in filtered.stdout


def test_strings_rejects_unknown_category(sample: Path):
    result = runner.invoke(app, ["strings", str(sample), "--category", "secrets"])
    assert result.exit_code == 2
    assert "is not a category" in result.output


def test_endpoints_command():
    result = runner.invoke(app, ["endpoints", str(FIXTURES / "endpoints.js"), "-f", "json"])
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert set(payload) == {
        "schema_version", "file", "endpoints", "domains", "unresolved_network_calls"
    }  # fmt: skip
    assert ("POST", "/api/orders") in {(e["method"], e["url"]) for e in payload["endpoints"]}

    text = runner.invoke(app, ["endpoints", str(FIXTURES / "endpoints.js")])
    assert text.exit_code == 0
    assert "/api/orders" in text.stdout
    assert "No request was made" in text.stdout


def test_deobfuscate_writes_separate_files(sample: Path, tmp_path: Path):
    before = sha256(sample)
    output_dir = tmp_path / "output"
    result = runner.invoke(app, ["deobfuscate", str(sample), "--output-dir", str(output_dir)])
    assert result.exit_code == 0
    assert sha256(sample) == before
    produced = output_dir / "sample.deobfuscated.js"
    assert produced.read_text() == (FIXTURES / "obfuscated_sample.expected.js").read_text()
    assert (output_dir / "transformations.json").exists()
    assert len(list((output_dir / "stages").iterdir())) == 4
    assert "fold-constants" in result.stdout
    assert str(produced) in result.stdout


def test_deobfuscate_defaults_to_a_named_directory(
    sample: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    monkeypatch.chdir(tmp_path)
    result = runner.invoke(app, ["deobfuscate", str(sample), "--no-stages"])
    assert result.exit_code == 0
    assert (tmp_path / "js-forensics-output" / "sample.deobfuscated.js").exists()
    assert not (tmp_path / "js-forensics-output" / "stages").exists()


def test_report_html(sample: Path, tmp_path: Path):
    output = tmp_path / "report.html"
    result = runner.invoke(
        app, ["report", str(sample), "--format", "html", "--output", str(output)]
    )
    assert result.exit_code == 0
    page = output.read_text()
    assert page.startswith("<!DOCTYPE html>")
    assert "Transformation history" not in page

    with_history = runner.invoke(
        app, ["report", str(sample), "--transformations", "-o", str(output)]
    )
    assert with_history.exit_code == 0
    assert "Transformation history" in output.read_text()


def test_report_default_output_name(sample: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.chdir(tmp_path)
    assert runner.invoke(app, ["report", str(sample)]).exit_code == 0
    assert (tmp_path / "sample.report.html").exists()
    assert runner.invoke(app, ["report", str(sample), "--format", "json"]).exit_code == 0
    assert json.loads((tmp_path / "sample.report.json").read_text())["schema_version"] == "1.0"


# --- failures ---------------------------------------------------------------


def test_missing_file(tmp_path: Path):
    result = runner.invoke(app, ["analyze", str(tmp_path / "missing.js")])
    assert result.exit_code == 3
    assert "does not exist" in result.output


def test_directory_instead_of_file(tmp_path: Path):
    result = runner.invoke(app, ["analyze", str(tmp_path)])
    assert result.exit_code == 3
    assert "is a directory" in result.output


def test_unreadable_file(tmp_path: Path):
    path = tmp_path / "locked.js"
    path.write_text("var a = 1;")
    path.chmod(0)
    try:
        if path.open("rb").readable():  # running as root; permissions do not apply
            pytest.skip("file permissions are not enforced for this user")
    except PermissionError:
        pass
    result = runner.invoke(app, ["analyze", str(path)])
    assert result.exit_code == 3
    assert "could not be read" in result.output


def test_oversized_file(sample: Path):
    result = runner.invoke(app, ["analyze", str(sample), "--max-bytes", "100"])
    assert result.exit_code == 3
    assert "larger than the 100-byte limit" in result.output
    assert "--max-bytes" in result.output


def test_non_utf8_file(tmp_path: Path):
    path = tmp_path / "latin1.js"
    path.write_bytes(b'var s = "caf\xe9";')
    result = runner.invoke(app, ["strings", str(path)])
    assert result.exit_code == 3
    assert "not valid UTF-8" in result.output


@pytest.mark.parametrize("command", ["analyze", "strings", "endpoints", "deobfuscate", "report"])
def test_malformed_javascript_is_rejected(command, tmp_path: Path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    result = runner.invoke(app, [command, str(FIXTURES / "malformed.js")])
    assert result.exit_code == 4
    assert "syntax error(s)" in result.output
    assert "line 1, column" in result.output
    assert list(tmp_path.iterdir()) == []  # nothing was written


def test_tolerant_analysis_of_malformed_javascript():
    result = runner.invoke(
        app, ["analyze", str(FIXTURES / "malformed.js"), "--tolerant", "-f", "json"]
    )
    assert result.exit_code == 0
    assert "results are partial" in result.stderr
    report = json.loads(result.stdout)
    assert report["parse"]["has_errors"] is True
    assert report["warnings"]


@pytest.mark.parametrize(
    "arguments",
    [
        ["analyze", "x.js", "--format", "xml"],
        ["report", "x.js", "--format", "text"],
        ["analyze"],
        ["analyze", "x.js", "--max-bytes", "0"],
        ["frobnicate", "x.js"],
    ],
)
def test_usage_errors(arguments):
    result = runner.invoke(app, arguments)
    assert result.exit_code == 2


def test_output_may_not_replace_the_input(sample: Path):
    before = sha256(sample)
    result = runner.invoke(app, ["analyze", str(sample), "-f", "json", "-o", str(sample)])
    assert result.exit_code == 5
    assert "Refusing to overwrite the input file" in result.output
    assert sha256(sample) == before


def test_unwritable_output(sample: Path, tmp_path: Path):
    blocker = tmp_path / "blocker"
    blocker.write_text("a file, not a directory")
    result = runner.invoke(app, ["report", str(sample), "-o", str(blocker / "report.html")])
    assert result.exit_code == 5
    assert "could not be written" in result.output


# --- installed entry point --------------------------------------------------

ENTRY_POINT = Path(sys.executable).parent / "js-forensics"
needs_entry_point = pytest.mark.skipif(
    not ENTRY_POINT.exists(), reason="the js-forensics console script is not installed"
)


@needs_entry_point
def test_installed_entry_point_reports_its_version():
    completed = subprocess.run([ENTRY_POINT, "--version"], capture_output=True, text=True)
    assert completed.returncode == 0
    assert completed.stdout.strip() == f"js-forensics {__version__}"


@needs_entry_point
def test_installed_entry_point_keeps_stdout_machine_readable(sample: Path):
    completed = subprocess.run(
        [ENTRY_POINT, "analyze", str(sample), "--format", "json"], capture_output=True, text=True
    )
    assert completed.returncode == 0
    assert completed.stderr == ""
    assert json.loads(completed.stdout)["file"]["path"] == str(sample)


@needs_entry_point
def test_installed_entry_point_exit_code_for_bad_syntax():
    completed = subprocess.run(
        [ENTRY_POINT, "analyze", str(FIXTURES / "malformed.js")], capture_output=True, text=True
    )
    assert completed.returncode == 4
    assert completed.stdout == ""
    assert "syntax error" in completed.stderr


def test_module_invocation():
    completed = subprocess.run(
        [sys.executable, "-m", "js_forensics", "--version"], capture_output=True, text=True
    )
    assert completed.returncode == 0
    assert completed.stdout.strip() == f"js-forensics {__version__}"


# --- documentation ----------------------------------------------------------

REPOSITORY = FIXTURES.parent.parent


def test_readme_quick_start_commands_work(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    example = REPOSITORY / "examples" / "sample.js"
    before = sha256(example)
    monkeypatch.chdir(tmp_path)
    commands = [
        ["analyze", str(example)],
        ["analyze", str(example), "--format", "json", "--output", "report.json"],
        ["strings", str(example)],
        ["endpoints", str(example)],
        ["deobfuscate", str(example), "--output-dir", "output/"],
        ["report", str(example), "--format", "html", "--output", "report.html"],
    ]
    for arguments in commands:
        # The README must show these exact invocations.
        assert (
            "js-forensics " + " ".join(arguments).replace(str(example), "examples/sample.js")
            in (REPOSITORY / "README.md").read_text()
        )
        assert runner.invoke(app, arguments).exit_code == 0, arguments
    assert json.loads((tmp_path / "report.json").read_text())["obfuscation"]["score"] == 45
    assert (tmp_path / "report.html").exists()
    # The README shows this file's contents as the deobfuscate result.
    produced = (tmp_path / "output" / "sample.deobfuscated.js").read_text()
    assert produced.strip() in (REPOSITORY / "README.md").read_text()
    assert sha256(example) == before
