# Security Policy

## Supported versions

Only the latest release receives security fixes.

## What counts as a vulnerability

JS Forensics is run on files that may be hostile, so these are treated as
security bugs:

- any way an analyzed file can get code executed, in JS Forensics itself or
  in a JavaScript runtime;
- any network request caused by analyzing a file;
- any write to the analyzed file, or outside the requested output location;
- script or markup from an analyzed file being active in an HTML report;
- terminal escape sequences from an analyzed file reaching the terminal
  unescaped;
- a small input that makes the tool hang or exhaust memory within the default
  size limit.

Not vulnerabilities, though still worth a normal issue: a credential that
redaction missed (redaction is documented as best-effort), a wrong
classification or score, and a transformation that changes program meaning.

## Reporting

Please do not open a public issue for a security bug. Use GitHub's private
reporting instead:
<https://github.com/stackadnan/js-forensics/security/advisories/new>

Include the JS Forensics version, the Python version, the command you ran,
and the smallest input that shows the problem. Do not attach live malware;
reduce the sample to the few lines that trigger the bug.

You can expect an acknowledgement within a week. Once a fix is released, the
advisory is published and you are credited unless you ask not to be.
