"""Unit tests for renaming decompiler-generated variables."""

import sys
from contextlib import nullcontext
from types import SimpleNamespace
from unittest.mock import Mock

from pyghidra_mcp.tools import GhidraTools


class _JavaIterator:
    def __init__(self, values):
        self._values = iter(values)
        self._next = None

    def hasNext(self):  # noqa: N802 - mirrors java.util.Iterator
        try:
            self._next = next(self._values)
        except StopIteration:
            return False
        return True

    def next(self):
        value = self._next
        self._next = None
        return value


def test_resolve_decompiler_variable_matches_exact_non_global_name(monkeypatch):
    tools = GhidraTools.__new__(GhidraTools)

    wanted = Mock()
    wanted.getName.return_value = "pbVar4"
    wanted.isGlobal.return_value = False
    wanted.isParameter.return_value = False
    global_symbol = Mock()
    global_symbol.getName.return_value = "pbVar4"
    global_symbol.isGlobal.return_value = True

    symbol_map = Mock()
    symbol_map.getSymbols.return_value = _JavaIterator([global_symbol, wanted])
    high_function = Mock()
    high_function.getLocalSymbolMap.return_value = symbol_map
    result = Mock()
    result.getErrorMessage.return_value = ""
    result.getHighFunction.return_value = high_function
    decompiler = Mock()
    decompiler.decompileFunction.return_value = result
    tools.decompiler_pool = Mock()
    tools.decompiler_pool.acquire.return_value = nullcontext(decompiler)

    monkeypatch.setitem(
        sys.modules,
        "ghidra.util.task",
        SimpleNamespace(ConsoleTaskMonitor=Mock),
    )

    function = Mock()
    kind, symbol = tools._resolve_decompiler_variable(function, "pbVar4")

    assert kind == "decompiler_local"
    assert symbol is wanted


def test_rename_variable_persists_decompiler_high_symbol(monkeypatch):
    tools = GhidraTools.__new__(GhidraTools)
    tools.program = Mock()
    tools.invalidate_decompiler_cache = Mock()

    entry_point = Mock()
    entry_point.__str__ = Mock(return_value="00016d00")
    function = Mock()
    function.getName.return_value = "MotorController_MainLoop"
    function.getEntryPoint.return_value = entry_point
    function.getParameters.return_value = []
    function.getLocalVariables.return_value = []
    tools.find_function = Mock(return_value=function)

    high_symbol = Mock()
    tools._resolve_decompiler_variable = Mock(
        return_value=("decompiler_local", high_symbol)
    )

    update_db_variable = Mock()
    user_defined = object()
    monkeypatch.setitem(
        sys.modules,
        "ghidra.program.model.pcode",
        SimpleNamespace(
            HighFunctionDBUtil=SimpleNamespace(updateDBVariable=update_db_variable)
        ),
    )
    monkeypatch.setitem(
        sys.modules,
        "ghidra.program.model.symbol",
        SimpleNamespace(SourceType=SimpleNamespace(USER_DEFINED=user_defined)),
    )
    monkeypatch.setattr(
        "pyghidra_mcp.tools.ghidra_transaction",
        lambda *_args, **_kwargs: nullcontext(),
    )

    result = tools.rename_variable(
        "MotorController_MainLoop", "pbVar4", "radio_pending_flags"
    )

    tools._resolve_decompiler_variable.assert_called_once_with(function, "pbVar4")
    update_db_variable.assert_called_once_with(
        high_symbol, "radio_pending_flags", None, user_defined
    )
    tools.invalidate_decompiler_cache.assert_called_once_with()
    assert result == {
        "function_name": "MotorController_MainLoop",
        "function_address": "00016d00",
        "variable_kind": "decompiler_local",
        "old_name": "pbVar4",
        "new_name": "radio_pending_flags",
    }


def test_rename_variable_keeps_database_local_fast_path(monkeypatch):
    tools = GhidraTools.__new__(GhidraTools)
    tools.program = Mock()
    tools.invalidate_decompiler_cache = Mock()

    entry_point = Mock()
    entry_point.__str__ = Mock(return_value="00016d00")
    local = Mock()
    local.getName.return_value = "local_10"
    function = Mock()
    function.getName.return_value = "MotorController_MainLoop"
    function.getEntryPoint.return_value = entry_point
    function.getParameters.return_value = []
    function.getLocalVariables.return_value = [local]
    tools.find_function = Mock(return_value=function)
    tools._resolve_decompiler_variable = Mock()

    update_db_variable = Mock()
    user_defined = object()
    monkeypatch.setitem(
        sys.modules,
        "ghidra.program.model.pcode",
        SimpleNamespace(
            HighFunctionDBUtil=SimpleNamespace(updateDBVariable=update_db_variable)
        ),
    )
    monkeypatch.setitem(
        sys.modules,
        "ghidra.program.model.symbol",
        SimpleNamespace(SourceType=SimpleNamespace(USER_DEFINED=user_defined)),
    )
    monkeypatch.setattr(
        "pyghidra_mcp.tools.ghidra_transaction",
        lambda *_args, **_kwargs: nullcontext(),
    )

    result = tools.rename_variable(
        "MotorController_MainLoop", "local_10", "packet_length"
    )

    local.setName.assert_called_once_with("packet_length", user_defined)
    tools._resolve_decompiler_variable.assert_not_called()
    update_db_variable.assert_not_called()
    assert result["variable_kind"] == "local"
