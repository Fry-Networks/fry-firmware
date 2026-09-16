Import("env")
import os, pathlib
tok = os.environ.get("FRY_API_TOKEN", "")
out = pathlib.Path(env.subst("$PROJECT_INCLUDE_DIR")) / "generated"
out.mkdir(parents=True, exist_ok=True)
esc = tok.replace("\\", "\\\\").replace('"', '\\"')
(out / "fry_secrets.h").write_text('#pragma once\n#define FRY_API_TOKEN "%s"\n' % esc)
print("fry_prebuild: api token %s" % ("present (%d chars)" % len(tok) if tok else "EMPTY - registration disabled in this build"))
for k in ("PROJECT_DIR", "PROJECT_CORE_DIR"):
    p = env.subst("$" + k)
    env.Append(CCFLAGS=["-ffile-prefix-map=%s=." % p, "-fmacro-prefix-map=%s=." % p])

# Strip the build-env name out of library __FILE__ strings.
#
# The maps above rewrite $PROJECT_DIR, but SCons hands GCC a path RELATIVE to the project for
# anything inside it, so library sources never carry the $PROJECT_DIR prefix and never match.
# What survives into the binary is the env name: NimBLE's assert() macros expand __FILE__, and
# `pio run -e esp32` vs `-e esp32_wroom32` then differ by (env-name length delta) x 14 embedded
# strings, for two builds that are otherwise the same firmware. Measured: exactly 112 bytes
# between those two envs, plus the link-address shift those bytes cause.
#
# Two relative keys are needed because the two libraries arrive in different shapes - 13 NimBLE
# paths carry a leading slash and esp_wireguard's does not - and GCC anchors a prefix match at
# position 0, so one key cannot cover both. The absolute key is belt-and-braces for a host where
# SCons does emit absolute paths; harmless when it matches nothing.
#
# ORDER MATTERS AND IS THE OPPOSITE OF THE OBVIOUS ONE. GCC prepends each -f*-prefix-map to a list
# and takes the FIRST match, so the map given LAST on the command line wins - it does not prefer
# the longest or most specific prefix. Verified against xtensa-esp32-elf-gcc 8.4.0 and
# xtensa-lx106-elf-gcc 10.3.0. These must therefore be appended AFTER the $PROJECT_DIR loop above,
# or the broader map would swallow them.
#
# Every key keeps its trailing separator: without it, the key for env "esp32" would also prefix-
# match "esp32s3" and "esp32_wroom32" and splice their paths into nonsense.
_pioenv = env.subst("$PIOENV")
_libdeps_abs = os.path.join(env.subst("$PROJECT_LIBDEPS_DIR"), _pioenv).replace("\\", "/")
for _key, _val in (
    (_libdeps_abs + "/", "libdeps/"),
    ("/.pio/libdeps/%s/" % _pioenv, "/libdeps/"),
    (".pio/libdeps/%s/" % _pioenv, "libdeps/"),
):
    env.Append(CCFLAGS=["-ffile-prefix-map=%s=%s" % (_key, _val)])
