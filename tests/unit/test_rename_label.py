"""Unit tests for label renaming."""

import sys
from contextlib import nullcontext
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from pyghidra_mcp.tools import GhidraTools


def _make_tools():
    tools = GhidraTools.__new__(GhidraTools)
    tools.program = Mock()
    tools.decompiler_pool = Mock()
    tools.invalidate_decompiler_cache = Mock()
    return tools


def _install_symbol_module(monkeypatch):
    label_type = object()
    user_defined = object()
    symbol_module = SimpleNamespace(
        SourceType=SimpleNamespace(USER_DEFINED=user_defined),
        SymbolType=SimpleNamespace(LABEL=label_type),
    )
    monkeypatch.setitem(sys.modules, "ghidra.program.model.symbol", symbol_module)
    return label_type, user_defined


def test_rename_label_renames_user_defined_symbol(monkeypatch):
    tools = _make_tools()
    label_type, user_defined = _install_symbol_module(monkeypatch)
    monkeypatch.setattr(
        "pyghidra_mcp.tools.ghidra_transaction",
        lambda *_args, **_kwargs: nullcontext(),
    )

    address = Mock()
    address.__str__ = Mock(return_value="1000042e3")
    symbol = Mock()
    symbol.getSymbolType.return_value = label_type
    symbol.getName.return_value = "LAB_1000042e3"
    symbol.getAddress.return_value = address
    tools.find_symbol = Mock(return_value=symbol)

    result = tools.rename_label("LAB_1000042e3", "parse_header")

    symbol.setName.assert_called_once_with("parse_header", user_defined)
    tools.invalidate_decompiler_cache.assert_called_once_with()
    assert result == {
        "address": "1000042e3",
        "old_name": "LAB_1000042e3",
        "new_name": "parse_header",
    }


def test_rename_label_rejects_non_label_symbols(monkeypatch):
    tools = _make_tools()
    _install_symbol_module(monkeypatch)
    symbol = Mock()
    symbol.getSymbolType.return_value = "Function"
    tools.find_symbol = Mock(return_value=symbol)

    with pytest.raises(ValueError, match="not a label"):
        tools.rename_label("main", "entry")

    symbol.setName.assert_not_called()
    tools.invalidate_decompiler_cache.assert_not_called()
