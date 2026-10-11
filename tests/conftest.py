from __future__ import annotations

import socket
from pathlib import Path

import pytest

from js_forensics.parser import ParsedSource

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture(autouse=True)
def no_network(monkeypatch: pytest.MonkeyPatch) -> None:
    """Analysis must stay offline, so any socket use fails the test."""

    def refuse(*args: object, **kwargs: object) -> None:
        raise AssertionError("js-forensics attempted to open a network socket")

    monkeypatch.setattr(socket, "socket", refuse)
    monkeypatch.setattr(socket, "create_connection", refuse)


def parse(source: str) -> ParsedSource:
    parsed = ParsedSource(source.encode("utf-8"))
    assert not parsed.has_errors, f"test source does not parse: {source!r}"
    return parsed


def parse_fixture(name: str) -> ParsedSource:
    path = FIXTURES / name
    return ParsedSource(path.read_bytes(), path=str(path))
