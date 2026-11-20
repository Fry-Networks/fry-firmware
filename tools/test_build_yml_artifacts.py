# Guard test for .github/workflows/build.yml: untagged and pull-request runs must not compile the CI
# secret into a firmware image, and must not publish build artifacts.
#
# build.yml compiles every push, every pull request and every manual dispatch. Only a v* tag run
# feeds the `release` job, so only a tag run may (a) receive the CI secret and (b) upload the
# `firmware-<env>` artifacts that job downloads. Everything else builds with an empty token and
# uploads nothing.
#
# Dependency-free (no YAML library), same style as the other tools/test_*.py:
#
#   python3 tools/test_build_yml_artifacts.py                   # check the sibling workflow file
#   python3 tools/test_build_yml_artifacts.py <path-to-a-copy>  # check a specific copy (pre-fix proof)
#   python3 tools/test_build_yml_artifacts.py <build.yml> <fault-images.yml>   # also pick the fault-images copy
#
# fault-images.yml is held to the same rule: its token is compiled in only on a v* tag ref, and its
# upload step carries a condition that names the tag ref.
#
# Exit 0 = all pass, 1 = a failure. The checker is first shown to catch each defect on built-in
# samples, then run on the workflow file.
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT = os.path.join(HERE, "..", ".github", "workflows", "build.yml")
FAULT_DEFAULT = os.path.join(HERE, "..", ".github", "workflows", "fault-images.yml")

TAG_GUARD = "startsWith(github.ref, 'refs/tags/v')"


def jobs_of(lines):
    """{job name: (first line index, last line index + 1)} for the entries under `jobs:`."""
    start = None
    for i, line in enumerate(lines):
        if line.rstrip() == "jobs:":
            start = i + 1
            break
    out = {}
    if start is None:
        return out
    name = None
    first = None
    for i in range(start, len(lines)):
        m = re.match(r"^  ([A-Za-z0-9_-]+):\s*$", lines[i])
        if m:
            if name is not None:
                out[name] = (first, i)
            name = m.group(1)
            first = i
        elif lines[i].strip() and not lines[i].startswith(" ") and not lines[i].startswith("#"):
            break
    if name is not None:
        out[name] = (first, len(lines))
    return out


def steps_of(lines, lo, hi):
    """Each step (a list item at indent 6) of the job spanning lines[lo:hi], as a list of lines."""
    steps = []
    cur = None
    for i in range(lo, hi):
        line = lines[i]
        if re.match(r"^      - ", line):
            if cur is not None:
                steps.append(cur)
            cur = [line]
        elif cur is not None:
            if line.strip() == "" or line.startswith("#") or len(line) - len(line.lstrip()) > 6:
                cur.append(line)
            else:
                steps.append(cur)
                cur = None
    if cur is not None:
        steps.append(cur)
    return steps


def check(text):
    """The list of problems found in a build.yml text (empty = fine)."""
    problems = []
    lines = text.splitlines()
    jobs = jobs_of(lines)
    if "build" not in jobs or "release" not in jobs:
        return ["jobs build and release are expected"]

    # (a) every use of the secret is tag-conditional, with an empty-string fallback
    uses = [(i, l) for i, l in enumerate(lines) if "secrets.FRY_API_TOKEN" in l]
    if not uses:
        problems.append("no step receives the CI secret on a tag run (the release build lost its token)")
    for i, l in uses:
        if TAG_GUARD not in l or "|| ''" not in l:
            problems.append("line %d hands the CI secret to every run: %s" % (i + 1, l.strip()))

    # (b) every artifact upload is tag-conditional
    uploads = 0
    for job, (lo, hi) in jobs.items():
        for step in steps_of(lines, lo, hi):
            if not any("actions/upload-artifact" in l for l in step):
                continue
            uploads += 1
            guarded = any(re.match(r"^\s+(- )?if:\s", l) and TAG_GUARD in l for l in step)
            if not guarded:
                problems.append("job %s: an upload-artifact step runs on every build: %s" % (job, step[0].strip()))
    if uploads == 0:
        problems.append("no upload-artifact step found (the release job would have nothing to download)")

    # (c) the tag path is unchanged: the release job is tag-only and still downloads the artifacts
    lo, hi = jobs["release"]
    head = "\n".join(lines[lo:hi][:8])
    if TAG_GUARD not in head:
        problems.append("the release job is no longer limited to tag runs")
    if not any("actions/download-artifact" in "\n".join(s) for s in steps_of(lines, lo, hi)):
        problems.append("the release job no longer downloads the firmware artifacts")
    return problems


GOOD = """name: build
on:
  push:
    tags: ['v*']
  pull_request:
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Build
        env:
          FRY_API_TOKEN: ${{ startsWith(github.ref, 'refs/tags/v') && secrets.FRY_API_TOKEN || '' }}
        run: pio run

      - uses: actions/upload-artifact@v4
        if: startsWith(github.ref, 'refs/tags/v')
        with:
          name: firmware
          path: firmware.bin

  release:
    needs: [build]
    if: startsWith(github.ref, 'refs/tags/v')
    runs-on: ubuntu-latest
    steps:
      - name: Download all firmware artifacts
        uses: actions/download-artifact@v4
"""

passed = 0
failed = 0


def expect(name, ok, detail=""):
    global passed, failed
    if ok:
        passed += 1
        print("ok    %s" % name)
    else:
        failed += 1
        print("FAIL  %s %s" % (name, detail))


def selftest():
    expect("sample: the guarded workflow has no problem", check(GOOD) == [], str(check(GOOD)))
    bad_token = GOOD.replace("startsWith(github.ref, 'refs/tags/v') && secrets.FRY_API_TOKEN || ''",
                             "secrets.FRY_API_TOKEN")
    expect("sample: the secret handed to every run is caught", bad_token != GOOD and len(check(bad_token)) == 1,
           str(check(bad_token)))
    no_fallback = GOOD.replace("secrets.FRY_API_TOKEN || ''", "secrets.FRY_API_TOKEN")
    expect("sample: a tag guard without the empty fallback is caught", no_fallback != GOOD and check(no_fallback) != [])
    bad_upload = GOOD.replace("        if: startsWith(github.ref, 'refs/tags/v')\n        with:", "        with:")
    expect("sample: an unguarded upload is caught", bad_upload != GOOD and len(check(bad_upload)) == 1,
           str(check(bad_upload)))
    no_release_guard = GOOD.replace("    needs: [build]\n    if: startsWith(github.ref, 'refs/tags/v')\n",
                                    "    needs: [build]\n")
    expect("sample: a release job open to every run is caught", no_release_guard != GOOD and check(no_release_guard) != [])
    no_download = GOOD.replace("actions/download-artifact@v4", "actions/cache@v4")
    expect("sample: a release job without its download is caught", no_download != GOOD and check(no_download) != [])
    expect("sample: a workflow without the jobs is rejected", check("name: x\n") != [])


def check_fault(text):
    """The list of problems found in a fault-images.yml text (empty = fine). The fault-image workflow may
    compile the CI secret in only on a v* tag ref (with an empty-string fallback), and an artifact upload
    must carry a condition that names the tag ref, so a request for the token on any other ref neither
    receives it nor publishes a build."""
    problems = []
    lines = text.splitlines()
    jobs = jobs_of(lines)
    if not jobs:
        return ["no jobs found"]
    for i, l in enumerate(lines):
        if l.lstrip().startswith("#"):
            continue
        if "secrets.FRY_API_TOKEN" in l and (TAG_GUARD not in l or "|| ''" not in l):
            problems.append("line %d hands the CI secret to runs that are not tag runs: %s" % (i + 1, l.strip()))
    for job, (lo, hi) in jobs.items():
        for step in steps_of(lines, lo, hi):
            if not any("actions/upload-artifact" in l for l in step):
                continue
            guarded = any(re.match(r"^\s+(- )?if:\s", l) and TAG_GUARD in l for l in step)
            if not guarded:
                problems.append("job %s: an upload-artifact step has no tag condition: %s" % (job, step[0].strip()))
    return problems


GOOD_FAULT = """name: fault-images
on:
  workflow_dispatch:
    inputs:
      with_token:
        type: boolean
  push:
    branches: ['bench-faults/**']
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Build
        env:
          FRY_API_TOKEN: ${{ inputs.with_token && startsWith(github.ref, 'refs/tags/v') && secrets.FRY_API_TOKEN || '' }}
        run: pio run -e esp32s3

      - uses: actions/upload-artifact@v4
        if: ${{ !inputs.with_token || startsWith(github.ref, 'refs/tags/v') }}
        with:
          name: firmware-fault
          path: firmware.bin
"""


def selftest_fault():
    expect("fault sample: the guarded workflow has no problem", check_fault(GOOD_FAULT) == [], str(check_fault(GOOD_FAULT)))
    bad_token = GOOD_FAULT.replace("inputs.with_token && startsWith(github.ref, 'refs/tags/v') && secrets.FRY_API_TOKEN || ''",
                                   "inputs.with_token && secrets.FRY_API_TOKEN || ''")
    expect("fault sample: the secret handed to every with_token run is caught",
           bad_token != GOOD_FAULT and len(check_fault(bad_token)) == 1, str(check_fault(bad_token)))
    no_fallback = GOOD_FAULT.replace("secrets.FRY_API_TOKEN || ''", "secrets.FRY_API_TOKEN")
    expect("fault sample: a tag guard without the empty fallback is caught",
           no_fallback != GOOD_FAULT and len(check_fault(no_fallback)) == 1, str(check_fault(no_fallback)))
    bad_upload = GOOD_FAULT.replace("        if: ${{ !inputs.with_token || startsWith(github.ref, 'refs/tags/v') }}\n", "")
    expect("fault sample: an upload without a tag condition is caught",
           bad_upload != GOOD_FAULT and len(check_fault(bad_upload)) == 1, str(check_fault(bad_upload)))
    wrong_if = GOOD_FAULT.replace("${{ !inputs.with_token || startsWith(github.ref, 'refs/tags/v') }}", "${{ !inputs.with_token }}")
    expect("fault sample: an upload condition that never names the tag ref is caught",
           wrong_if != GOOD_FAULT and len(check_fault(wrong_if)) == 1, str(check_fault(wrong_if)))
    both = bad_upload.replace("inputs.with_token && startsWith(github.ref, 'refs/tags/v') && secrets.FRY_API_TOKEN || ''",
                              "inputs.with_token && secrets.FRY_API_TOKEN || ''")
    expect("fault sample: the secret and the upload defects are both reported", len(check_fault(both)) == 2, str(check_fault(both)))
    commented = GOOD_FAULT.replace("jobs:\n", "# the secret is read as secrets.FRY_API_TOKEN below\njobs:\n")
    expect("fault sample: a comment that names the secret is not a use", commented != GOOD_FAULT and check_fault(commented) == [],
           str(check_fault(commented)))
    expect("fault sample: a workflow without jobs is rejected", check_fault("name: x\n") != [])


def main():
    path = os.path.abspath(sys.argv[1]) if len(sys.argv) > 1 else os.path.abspath(DEFAULT)
    fault_path = os.path.abspath(sys.argv[2]) if len(sys.argv) > 2 else os.path.abspath(FAULT_DEFAULT)
    selftest()
    with open(path) as f:
        text = f.read()
    problems = check(text)
    expect("workflow file: untagged and pull-request runs get no secret and upload nothing", problems == [],
           "\n      " + "\n      ".join(problems))
    selftest_fault()
    with open(fault_path) as f:
        fault_problems = check_fault(f.read())
    expect("fault-images workflow file: the secret only on a tag ref, and a tag condition on every upload",
           fault_problems == [], "\n      " + "\n      ".join(fault_problems))
    print("%d passed, %d failed" % (passed, failed))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
