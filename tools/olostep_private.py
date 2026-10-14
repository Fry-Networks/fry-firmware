Import("env")
# Olostep opt-in builds only (the *_olostep envs). The executor is a privately built module; this
# links it into src/ so it compiles as part of the firmware (a library archive would not do: the
# linker will not pull a strong definition out of an archive when a weak stub already satisfies the
# symbol). Contract: the module lives at $FRY_OLOSTEP_DIR, default <project>/.private/olostep, and
# its src/ is exposed as src/olostep_private (gitignored). Every file in it is #if FRY_HAS_OLOSTEP.
import os
proj = env.subst("$PROJECT_DIR")
target = os.path.realpath(os.environ.get("FRY_OLOSTEP_DIR") or os.path.join(proj, ".private", "olostep"))
# The module's firmware sources live in its src/ subdirectory (tests and the host-test project stay
# outside the tree the firmware build compiles); a module without one is linked as-is.
if os.path.isdir(os.path.join(target, "src")):
    target = os.path.join(target, "src")
link = os.path.join(proj, "src", "olostep_private")
if not os.path.isdir(target):
    print("olostep_private: REFUSED - private module directory not found: %s" % target)
    print("olostep_private: set FRY_OLOSTEP_DIR or fetch the module into .private/olostep")
    env.Exit(1)
if os.path.islink(link):
    if os.path.realpath(link) != target:
        os.unlink(link)
        os.symlink(target, link)
elif os.path.exists(link):
    print("olostep_private: REFUSED - %s exists and is not a symlink" % link)
    env.Exit(1)
else:
    os.symlink(target, link)
print("olostep_private: src/olostep_private -> %s" % target)
