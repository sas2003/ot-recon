# tests/test_gui.py
#
# gui.py deliberately contains zero business logic of its own - it builds
# a GooeyParser form and dispatches to the exact same run_scan/run_diff/
# run_history functions main.py's CLI uses. So these tests don't need
# wxPython/Gooey running at all: they mock build_gui_parser() to return a
# fake Namespace and assert gui_main() calls the right run_* function.
# That's the whole contract gui.py needs to uphold.

from unittest.mock import patch, MagicMock
import argparse

from ot_recon import gui


def _args(command, **kwargs):
    return argparse.Namespace(command=command, **kwargs)


def test_gui_main_dispatches_scan():
    fake_args = _args("scan", target="10.0.0.0/24")

    with patch.object(gui, "build_gui_parser", return_value=fake_args), \
         patch.object(gui, "run_scan") as mock_run_scan, \
         patch.object(gui, "run_diff") as mock_run_diff, \
         patch.object(gui, "run_history") as mock_run_history:
        gui.gui_main()

    mock_run_scan.assert_called_once_with(fake_args)
    mock_run_diff.assert_not_called()
    mock_run_history.assert_not_called()


def test_gui_main_dispatches_diff():
    fake_args = _args("diff", from_snapshot=None, to_snapshot=None)

    with patch.object(gui, "build_gui_parser", return_value=fake_args), \
         patch.object(gui, "run_scan") as mock_run_scan, \
         patch.object(gui, "run_diff") as mock_run_diff, \
         patch.object(gui, "run_history") as mock_run_history:
        gui.gui_main()

    mock_run_diff.assert_called_once_with(fake_args)
    mock_run_scan.assert_not_called()
    mock_run_history.assert_not_called()


def test_gui_main_dispatches_history():
    fake_args = _args("history", limit=20)

    with patch.object(gui, "build_gui_parser", return_value=fake_args), \
         patch.object(gui, "run_scan") as mock_run_scan, \
         patch.object(gui, "run_diff") as mock_run_diff, \
         patch.object(gui, "run_history") as mock_run_history:
        gui.gui_main()

    mock_run_history.assert_called_once_with(fake_args)
    mock_run_scan.assert_not_called()
    mock_run_diff.assert_not_called()


def test_gui_main_dispatches_report():
    fake_args = _args("report", snapshot=None, out=None, no_diff=False)

    with patch.object(gui, "build_gui_parser", return_value=fake_args), \
         patch.object(gui, "run_scan") as mock_run_scan, \
         patch.object(gui, "run_report") as mock_run_report:
        gui.gui_main()

    mock_run_report.assert_called_once_with(fake_args)
    mock_run_scan.assert_not_called()


def test_gui_main_no_command_calls_nothing():
    """Gooey always shows the subcommand picker, but guard the case where
    no action matches anyway rather than silently assuming one."""

    fake_args = _args(None)

    with patch.object(gui, "build_gui_parser", return_value=fake_args), \
         patch.object(gui, "run_scan") as mock_run_scan, \
         patch.object(gui, "run_diff") as mock_run_diff, \
         patch.object(gui, "run_history") as mock_run_history:
        gui.gui_main()

    mock_run_scan.assert_not_called()
    mock_run_diff.assert_not_called()
    mock_run_history.assert_not_called()



# --- parser parity: GUI form must stay in sync with the CLI parser ---
#
# gui.py builds its own GooeyParser (it needs widget= hints), so nothing
# structural stops it drifting from main.build_parser(). That already
# happened once: --cve-live was added to the CLI, the GUI form wasn't
# updated, and every GUI scan then crashed with AttributeError inside
# run_scan - invisible to the dispatch tests above because they mock
# run_scan entirely. These tests compare the real parsers instead.

import pytest

from ot_recon.main import build_parser


def _parse(parser, argv):
    return vars(parser.parse_args(argv))


@pytest.mark.parametrize("argv", [
    ["scan", "10.0.0.0/24"],
    ["diff"],
    ["history"],
    ["report"],
])
def test_gui_parser_produces_same_args_and_defaults_as_cli_parser(argv):
    cli = _parse(build_parser(), argv)
    gui_ns = _parse(gui.make_gui_parser(), argv)

    assert set(gui_ns) == set(cli), (
        f"GUI and CLI parsers disagree on arguments for {argv[0]!r}: "
        f"only in CLI={sorted(set(cli) - set(gui_ns))}, "
        f"only in GUI={sorted(set(gui_ns) - set(cli))}"
    )
    assert gui_ns == cli  # same defaults too (None -> falls through to config)


def test_gui_scan_namespace_satisfies_everything_run_scan_reads():
    """Direct guard for the original bug: every args.<name> that run_scan
    touches must exist on the namespace the GUI produces."""

    import inspect
    import re
    from ot_recon import main as main_module

    needed = set(re.findall(r"args\.(\w+)", inspect.getsource(main_module.run_scan)))
    provided = set(_parse(gui.make_gui_parser(), ["scan", "10.0.0.0/24"]))

    assert needed <= provided, f"GUI scan form is missing: {sorted(needed - provided)}"


def test_gui_does_not_enable_richtext_console():
    """Regression: richtext_controls=True makes Gooey use RichTextConsole,
    which calls colored.style.ESC - removed in recent `colored` releases -
    so the entire GUI crashed with AttributeError the moment it started.
    That only showed up when gui.py was really launched (the parser/dispatch
    tests never start Gooey), so pin the known-bad option explicitly."""

    import inspect
    source = inspect.getsource(gui)
    code_lines = [l for l in source.splitlines() if not l.strip().startswith("#")]
    assert not any("richtext_controls" in l for l in code_lines)


def test_gui_sets_module_target_for_global_invocation():
    """Gooey defaults to sys.argv[0] as the command target when spawning its
    subprocess. On Windows, entry_point executables (Scripts/ot-recon-gui.exe)
    set sys.argv[0] to an extensionless path that does not exist on disk,
    causing python.exe to fail with [Errno 2] No such file or directory.
    Setting target to run via -m ot_recon.gui ensures it works globally."""
    rg = gui.build_gui_parser.__closure__[1].cell_contents
    gooey_params = [c.cell_contents for c in rg.__closure__ if isinstance(c.cell_contents, dict)][0]
    assert "-m ot_recon.gui" in gooey_params.get("target", "")

