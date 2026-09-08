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
