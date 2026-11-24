"""Read conventional APT sources and plan the single supported pocket change."""

import re
from pathlib import Path
from typing import NamedTuple

APT_BACKPORTS = "resolute-backports"
APT_LIST_LINE = re.compile(r"deb(?:-src)?\s+(?:\[([^]]*)\]\s+)?(\S+)\s+(\S+)(?:\s+.*)?")


class AptSource(NamedTuple):
    fields: dict
    location: str
    start: int
    end: int
    positions: dict


def apt_source_paths(root: Path):
    parts = root / "sources.list.d"
    return [root / "sources.list", *sorted(parts.glob("*.list")), *sorted(parts.glob("*.sources"))]


def apt_source_records(path, text):
    lines = text.splitlines(keepends=True)
    if path.suffix != ".sources":
        for index, raw in enumerate(lines):
            line = raw.split("#", 1)[0].strip()
            if not line:
                continue
            location = f"{path}:{index + 1}"
            match = APT_LIST_LINE.fullmatch(line)
            if not match:
                raise ValueError(f"Unrecognized APT source line in {location}.")
            options = {}
            for item in (match[1] or "").split():
                if "=" not in item:
                    continue
                key, value = item.split("=", 1)
                if key.lower() == "enabled":
                    raise ValueError(f"Enabled is a deb822 field and is unsupported in {location}.")
                if key in options:
                    raise ValueError(f"Duplicate APT option {key} in {location}.")
                options[key] = value
            yield AptSource({**options, "uris": match[2], "suites": match[3]}, location, index, index + 1, {})
        return

    start = 0
    fields, positions, last_key = {}, {}, None
    for index, raw in enumerate([*lines, ""]):
        location = f"{path} (stanza at line {start + 1})"
        if not raw.strip():
            if fields:
                yield AptSource(fields, location, start, index, positions)
            start = index + 1
            fields, positions, last_key = {}, {}, None
        elif raw.startswith("#"):
            continue
        elif raw[:1].isspace() and last_key:
            fields[last_key] += " " + raw.strip()
            positions[last_key].append(index)
        elif re.match(r"^[A-Za-z][A-Za-z0-9-]*:", raw):
            key, value = raw.split(":", 1)
            last_key = key.lower()
            if last_key in fields:
                raise ValueError(f"Duplicate deb822 APT field {key} in {location}.")
            fields[last_key] = value.strip()
            positions[last_key] = [index]
        else:
            raise ValueError(f"Malformed deb822 APT source at {path}:{index + 1}.")


def apt_source_enabled(fields):
    value = fields.get("enabled", "yes").strip().lower()
    # APT's deb822 parser accepts these aliases as well as numeric zero.
    return value not in {"no", "false", "without", "off", "disable"} and not re.fullmatch(r"[+-]?(?:0+|0x0+)", value)


def apt_backports_records(path, text):
    return [record for record in apt_source_records(path, text)
            if apt_source_enabled(record.fields) and APT_BACKPORTS in record.fields.get("suites", "").split()]


def without_apt_backports(path, text, records):
    lines = text.splitlines(keepends=True)
    for record in reversed(records):
        if path.suffix != ".sources":
            lines[record.start] = "# Disabled by SiteKit: " + lines[record.start]
            continue
        suites = record.fields["suites"].split()
        if any(suite != APT_BACKPORTS for suite in suites):
            for position in record.positions["suites"]:
                first = position == record.positions["suites"][0]
                prefix, value = lines[position].split(":", 1) if first else ("", lines[position])
                value = re.sub(r"(?<!\S)" + APT_BACKPORTS + r"(?!\S)", "", value)
                lines[position] = prefix + ":" + value if first else value if value.strip() else ""
        elif "enabled" in record.positions:
            first, *continuations = record.positions["enabled"]
            newline = "\r\n" if lines[first].endswith("\r\n") else "\n" if lines[first].endswith("\n") else ""
            lines[first] = lines[first].split(":", 1)[0] + ": no" + newline
            for position in continuations:
                lines[position] = ""
        else:
            newline = "\r\n" if lines[record.end - 1].endswith("\r\n") else "\n"
            if not lines[record.end - 1].endswith("\n"):
                lines[record.end - 1] += newline
            lines.insert(record.end, "Enabled: no" + newline)
    return "".join(lines)
