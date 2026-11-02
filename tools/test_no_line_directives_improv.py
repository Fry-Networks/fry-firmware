# Source pin: src/core/improv_serial_glue.cpp must carry no #line directive. A stale `#line 232`
# there skewed every later diagnostic/backtrace line number (its own comment said to drop it).
# Dependency-free; runs under pytest or directly.
import os
import re
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
SRC = os.path.join(ROOT, "src", "core", "improv_serial_glue.cpp")


def line_directives(code):
    return [n for n, l in enumerate(code.splitlines(), 1) if re.match(r"\s*#\s*line\b", l)]


def test_no_line_directive():
    with open(SRC, encoding="utf-8") as f:
        assert line_directives(f.read()) == []


def test_control_detects_directive():
    assert line_directives("int a;\n#line 232\nint b;\n") == [2]


if __name__ == "__main__":
    fails = 0
    for fn in (test_no_line_directive, test_control_detects_directive):
        try:
            fn()
            print("PASS", fn.__name__)
        except AssertionError as e:
            fails += 1
            print("FAIL", fn.__name__, e)
    sys.exit(1 if fails else 0)
