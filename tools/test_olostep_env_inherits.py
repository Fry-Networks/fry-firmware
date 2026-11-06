# Source pin: [env:esp8266_olostep] must build the same ESP8266 image layout as [env:esp8266]:
# the linker script, CPU frequency and filesystem come from env:esp8266 through `extends` and must
# not be overridden. Dependency-free; runs under pytest or directly:
#   python3 tools/test_olostep_env_inherits.py
import configparser
import os
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
KEYS = ("board_build.ldscript", "board_build.f_cpu", "board_build.filesystem")


def parse(text):
    cp = configparser.RawConfigParser(strict=False, interpolation=None, comment_prefixes=(";", "#"))
    cp.read_string(text)
    return cp


def effective(cp, section, key):
    """The value of `key` for `section`, following `extends` the way PlatformIO does (child wins)."""
    seen = set()
    while section not in seen:
        seen.add(section)
        if not cp.has_section(section):
            return None
        if cp.has_option(section, key):
            return cp.get(section, key).strip()
        if not cp.has_option(section, "extends"):
            return None
        section = cp.get(section, "extends").split(",")[0].strip()
        if not cp.has_section(section) and cp.has_section("env:" + section):
            section = "env:" + section
    return None


def problems(text):
    cp = parse(text)
    out = []
    for key in KEYS:
        base = effective(cp, "env:esp8266", key)
        olo = effective(cp, "env:esp8266_olostep", key)
        if not base:
            out.append("env:esp8266 has no %s" % key)
        elif olo != base:
            out.append("env:esp8266_olostep has %s=%r, env:esp8266 has %r" % (key, olo, base))
    return out


def read():
    with open(os.path.join(ROOT, "platformio.ini"), encoding="utf-8") as f:
        return f.read()


def test_olostep_inherits_the_image_layout():
    assert problems(read()) == []


def test_control_mutants_fail():
    text = read()
    marker = "[env:esp8266_olostep]\nextends = env:esp8266\n"
    assert marker in text
    for key, value in (("board_build.ldscript", "eagle.flash.1m.ld"),
                       ("board_build.f_cpu", "80000000L"),
                       ("board_build.filesystem", "spiffs")):
        assert problems(text.replace(marker, marker + "%s = %s\n" % (key, value))) != [], key
    # Dropping the extends makes every key come from nowhere.
    assert problems(text.replace(marker, "[env:esp8266_olostep]\n")) != []


if __name__ == "__main__":
    test_olostep_inherits_the_image_layout()
    test_control_mutants_fail()
    print("ok")
    sys.exit(0)
