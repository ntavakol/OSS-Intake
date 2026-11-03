#!/usr/bin/env python3
"""Write site/builder/options.json, the command builder's list of options, from the real argument parser.

    python scripts/export_options.py           # rewrite site/builder/options.json
    python scripts/export_options.py --check   # exit 1 if it is out of date (the test suite runs this)

Every option comes from oss_intake.cli.build_parser(); nothing is declared twice. An action type this script
does not know stops it with an error, so a new kind of option cannot be dropped from the builder unnoticed.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "site" / "builder" / "options.json"
sys.path.insert(0, str(ROOT / "src"))

from oss_intake import __version__  # noqa: E402
from oss_intake.cli import build_parser  # noqa: E402


def _internals(parser: argparse.ArgumentParser) -> tuple[dict[str, argparse.ArgumentParser], dict]:
    """The subcommand parsers, and each one's actions and mutually exclusive groups.

    argparse has no public API to list a parser's options, so this reads its private attributes (_actions,
    _mutually_exclusive_groups, _group_actions, and the subparsers action's choices). They have been stable
    for many Python versions; keeping every such access here means a change in argparse breaks one place."""
    subs = [a for a in parser._actions if isinstance(a, argparse._SubParsersAction)]
    if len(subs) != 1:
        raise SystemExit("export_options: expected exactly one set of subcommands")
    commands = dict(subs[0].choices)
    helps = {c.dest: c.help or "" for c in subs[0]._choices_actions}
    detail = {}
    for name, sp in commands.items():
        groups = [[a.dest for a in g._group_actions] for g in sp._mutually_exclusive_groups]
        required = [g.required for g in sp._mutually_exclusive_groups]
        detail[name] = {"actions": list(sp._actions), "groups": groups, "groups_required": required,
                        "help": helps.get(name, "")}
    return commands, detail


def _kind(action: argparse.Action) -> tuple[str, list | None]:
    """The builder's field kind for an argparse action, and its allowed values if it has a fixed list."""
    if isinstance(action, argparse._StoreTrueAction):
        return "flag", None
    if isinstance(action, argparse._AppendAction):
        return "repeatable", None
    if type(action) is argparse._StoreAction:
        if not action.option_strings:
            return "positional", None
        if action.choices is not None:
            return "choice", list(action.choices)
        if action.type is int:
            return "int", None
        if action.type in (None, str, str.upper):
            return "value", None
    raise SystemExit(f"export_options: {', '.join(action.option_strings) or action.dest}: "
                     f"{type(action).__name__} (type {action.type!r}) is not supported; teach the builder about it")


def export() -> dict:
    """Everything the builder needs, in a stable order."""
    commands, detail = _internals(build_parser())
    out: dict = {"generated_by": "scripts/export_options.py", "version": __version__, "commands": {}}
    for name in sorted(commands):
        info = detail[name]
        options = []
        for a in info["actions"]:
            if isinstance(a, (argparse._HelpAction, argparse._VersionAction)):
                continue
            kind, choices = _kind(a)
            group = next((i for i, g in enumerate(info["groups"]) if a.dest in g), None)
            default = a.default if a.default not in (None, argparse.SUPPRESS) else None
            options.append({
                "flag": max(a.option_strings, key=len) if a.option_strings else None,
                "dest": a.dest,
                "kind": kind,
                "help": a.help or "",
                "metavar": a.metavar if isinstance(a.metavar, str) else None,
                "default": default if default != [] else None,
                "choices": choices,
                "required": bool(a.required),
                "exclusive_group": group,
                "upper": a.type is str.upper,
            })
        out["commands"][name] = {
            "help": info["help"],
            "options": options,
            "exclusive_groups": [{"options": g, "required": r}
                                 for g, r in zip(info["groups"], info["groups_required"], strict=True)],
        }
    return out


def render() -> str:
    return json.dumps(export(), indent=1, sort_keys=True, ensure_ascii=False) + "\n"


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    p.add_argument("--check", action="store_true", help="exit 1 if options.json is out of date")
    args = p.parse_args(argv)
    text = render()
    if args.check:
        current = OUT.read_text(encoding="utf-8") if OUT.exists() else ""
        if current != text:
            print(f"{OUT.relative_to(ROOT)} is out of date: run python scripts/export_options.py", file=sys.stderr)
            return 1
        return 0
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(text, encoding="utf-8", newline="\n")
    print(f"wrote {OUT.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
