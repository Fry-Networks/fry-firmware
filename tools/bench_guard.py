"""Guard for the bench fault macro (include/bench_fault.h), used by tools/fry_prebuild.py.

FRY_BENCH_FAULT compiles a fault into a production env. It is allowed only when the fault-images
workflow marked the build (FRY_BENCH_BUILD=1 in the environment), on an ESP32-family production env,
with a fault number the bench uses (2-5). FRY_BENCH_IMAGE is defined by the header only and is never
accepted on a command line. Any other build that carries either name is refused, so a release build
fails instead of shipping a fault.
"""
import re

ALLOWED_FAULTS = ("2", "3", "4", "5")


def check(env_name, flags_text, environ):
    """Return None if the build is fine, else a one-line reason it must be refused."""
    has_fault = re.search(r"(?:(?<=-D)|(?<![A-Za-z0-9_]))FRY_BENCH_FAULT(?![A-Za-z0-9_])", flags_text) is not None
    has_image = re.search(r"(?:(?<=-D)|(?<![A-Za-z0-9_]))FRY_BENCH_IMAGE(?![A-Za-z0-9_])", flags_text) is not None
    if not has_fault and not has_image:
        return None
    if environ.get("FRY_BENCH_BUILD") != "1":
        return "FRY_BENCH_FAULT / FRY_BENCH_IMAGE in the flags of %s without the bench workflow marker" % env_name
    if has_image:
        return "FRY_BENCH_IMAGE must not be passed on a command line (include/bench_fault.h defines it)"
    if not env_name.startswith("esp32") or env_name.endswith("_test"):
        return "FRY_BENCH_FAULT is only for ESP32-family production envs, not %s" % env_name
    values = re.findall(r"(?:(?<=-D)|(?<![A-Za-z0-9_]))FRY_BENCH_FAULT=(\S*)", flags_text)
    # PlatformIO folds PLATFORMIO_BUILD_FLAGS into the project's build_flags, so the same value can be seen twice.
    if len(set(values)) != 1 or values[0] not in ALLOWED_FAULTS:
        return "FRY_BENCH_FAULT must be one value in 2-5 (got %r)" % (values,)
    return None
