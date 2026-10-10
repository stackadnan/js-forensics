"""Exceptions and the exit codes the CLI maps them to."""

from __future__ import annotations

from enum import IntEnum
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from js_forensics.models import SyntaxIssue


class ExitCode(IntEnum):
    OK = 0
    UNEXPECTED = 1
    USAGE = 2  # raised by the CLI framework for invalid options
    INPUT = 3  # file missing, unreadable, too large, or not UTF-8
    SYNTAX = 4  # the JavaScript could not be parsed cleanly
    OUTPUT = 5  # the requested output could not be written


class JSForensicsError(Exception):
    exit_code = ExitCode.UNEXPECTED


class InputError(JSForensicsError):
    exit_code = ExitCode.INPUT


class OutputError(JSForensicsError):
    exit_code = ExitCode.OUTPUT


class JavaScriptSyntaxError(JSForensicsError):
    exit_code = ExitCode.SYNTAX

    def __init__(self, path: str, issues: list[SyntaxIssue], total: int) -> None:
        self.path = path
        self.issues = issues
        self.total = total
        first = issues[0]
        super().__init__(
            f"{path}: {total} syntax error(s); first at line {first.location.line}, "
            f"column {first.location.column}: {first.message}"
        )
