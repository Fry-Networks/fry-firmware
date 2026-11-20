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


# The fault-image workflow is also held to the exact expressions, not only to the presence of the tag
# text: a token expression or an upload condition that merely mentions the tag ref can still hand the
# secret to a non-tag run or publish a build that asked for it.
FAULT_TOKEN_LINE = "FRY_API_TOKEN: ${{ inputs.with_token && startsWith(github.ref, 'refs/tags/v') && secrets.FRY_API_TOKEN || '' }}"
FAULT_UPLOAD_IF = "${{ !inputs.with_token || startsWith(github.ref, 'refs/tags/v') }}"


def step_values(step, key):
    """The values of every `key:` line (also `- key:`) of one step, trailing blanks removed."""
    out = []
    for l in step:
        m = re.match(r"^\s+(?:- )?%s:\s*(.*?)\s*$" % re.escape(key), l)
        if m:
            out.append(m.group(1))
    return out


def input_block(lines, name):
    """The lines of the workflow_dispatch input `name` (its key line and the more deeply indented lines below it)."""
    for i, l in enumerate(lines):
        m = re.match(r"^(\s+)%s:\s*$" % re.escape(name), l)
        if m:
            ind = len(m.group(1))
            blk = [l]
            for k in lines[i + 1:]:
                if k.strip() and len(k) - len(k.lstrip()) <= ind:
                    break
                blk.append(k)
            return blk
    return None


def check_fault_exact(text):
    """Problems of a fault-images.yml text against the exact conditions (empty = fine): the only use of a
    secret is the one token line, character for character; every upload step has exactly one `if:` and it is
    the exact upload condition; the with_token input is a boolean that defaults to false."""
    problems = []
    lines = text.splitlines()
    jobs = jobs_of(lines)
    if not jobs:
        return ["no jobs found"]
    uses = [(i, l.strip()) for i, l in enumerate(lines) if not l.lstrip().startswith("#") and "secrets." in l]
    for i, l in uses:
        if l != FAULT_TOKEN_LINE:
            problems.append("line %d is not the exact token line: %s" % (i + 1, l))
    if len(uses) != 1:
        problems.append("expected exactly one use of a secret, found %d" % len(uses))
    uploads = 0
    for job, (lo, hi) in jobs.items():
        for step in steps_of(lines, lo, hi):
            if not any("actions/upload-artifact" in l for l in step):
                continue
            uploads += 1
            conds = step_values(step, "if")
            if conds != [FAULT_UPLOAD_IF]:
                problems.append("job %s: the upload condition is %s, expected [%r]" % (job, conds, FAULT_UPLOAD_IF))
    if uploads == 0:
        problems.append("no upload-artifact step found")
    blk = input_block(lines, "with_token")
    if blk is None:
        problems.append("the with_token input is missing")
    else:
        if step_values(blk, "type") != ["boolean"]:
            problems.append("with_token is not a boolean input")
        if step_values(blk, "default") != ["false"]:
            problems.append("with_token does not default to false")
    return problems


def selftest_fault_exact():
    good = GOOD_FAULT.replace("type: boolean", "type: boolean\n        default: false")
    expect("fault exact sample: the exact workflow has no problem", good != GOOD_FAULT and check_fault_exact(good) == [],
           str(check_fault_exact(good)))
    w5 = good.replace("inputs.with_token && startsWith", "startsWith")
    expect("fault exact sample w5: a token expression without the with_token operand is caught",
           w5 != good and check_fault_exact(w5) != [], str(check_fault_exact(w5)))
    w6 = good.replace("if: ${{ !inputs.with_token ||", "if: ${{ inputs.with_token ||")
    expect("fault exact sample w6: an upload condition with the with_token operand flipped is caught",
           w6 != good and check_fault_exact(w6) != [], str(check_fault_exact(w6)))
    w7 = good.replace("inputs.with_token && startsWith(github.ref, 'refs/tags/v') && secrets.FRY_API_TOKEN",
                      "startsWith(github.ref, 'refs/tags/v') || inputs.with_token && secrets.FRY_API_TOKEN")
    expect("fault exact sample w7: a token expression that an untagged with_token run satisfies is caught",
           w7 != good and check_fault_exact(w7) != [] and check_fault(w7) == [], str(check_fault_exact(w7)))
    w8 = good.replace("startsWith(github.ref, 'refs/tags/v') }}\n        with:", "startsWith(github.ref, 'refs/tags/v') || true }}\n        with:")
    expect("fault exact sample w8: an upload condition that is always true is caught",
           w8 != good and check_fault_exact(w8) != [] and check_fault(w8) == [], str(check_fault_exact(w8)))
    second = good.replace("        run: pio run -e esp32s3\n", "        run: pio run -e esp32s3\n      - run: echo ${{ secrets.OTHER_VALUE }}\n")
    expect("fault exact sample: a second use of a secret is caught", second != good and check_fault_exact(second) != [],
           str(check_fault_exact(second)))
    noif = good.replace("        if: ${{ !inputs.with_token || startsWith(github.ref, 'refs/tags/v') }}\n", "")
    expect("fault exact sample: an upload without a condition is caught", noif != good and check_fault_exact(noif) != [],
           str(check_fault_exact(noif)))
    twoif = good.replace("        if: ${{ !inputs.with_token || startsWith(github.ref, 'refs/tags/v') }}\n",
                         "        if: ${{ !inputs.with_token || startsWith(github.ref, 'refs/tags/v') }}\n        if: true\n")
    expect("fault exact sample: a second if: on the upload is caught", twoif != good and check_fault_exact(twoif) != [],
           str(check_fault_exact(twoif)))
    dflt = good.replace("default: false", "default: true")
    expect("fault exact sample: with_token defaulting to true is caught", dflt != good and check_fault_exact(dflt) != [],
           str(check_fault_exact(dflt)))
    nodef = GOOD_FAULT
    expect("fault exact sample: with_token without a default is caught", check_fault_exact(nodef) != [], str(check_fault_exact(nodef)))
    comment = good.replace("jobs:\n", "# a note that names secrets.FRY_API_TOKEN\njobs:\n")
    expect("fault exact sample: a comment that names the secret is not a use", comment != good and check_fault_exact(comment) == [],
           str(check_fault_exact(comment)))
    expect("fault exact sample: a workflow without jobs is rejected", check_fault_exact("name: x\n") != [])


# build.yml is held to the exact expressions as well, and both workflows are scanned for the word
# `secrets` in any syntax (secrets.X, secrets['X'], toJSON(secrets), `secrets: inherit`), not only the
# dotted form: a token expression, an upload condition or a job condition that merely contains the tag
# text can still be true on a run that is not a tag run.
BUILD_TOKEN_LINE = "FRY_API_TOKEN: ${{ startsWith(github.ref, 'refs/tags/v') && secrets.FRY_API_TOKEN || '' }}"
BUILD_TAG_JOBS = ("flasher-assets", "release")


def secret_word_problems(text, exact_line):
    """Problems of a workflow text about secrets (empty = fine): every line that carries the word `secrets`
    is the exact token line, and that line occurs exactly once. A comment line is skipped unless it holds a
    `${{` expression (inside a run block such a line is still evaluated)."""
    problems = []
    n_exact = 0
    for i, l in enumerate(text.splitlines()):
        if not re.search(r"\bsecrets\b", l):
            continue
        s = l.strip()
        if s == exact_line:
            n_exact += 1
            continue
        if s.startswith("#") and "${{" not in s:
            continue
        problems.append("line %d uses a secret outside the exact token line: %s" % (i + 1, s[:100]))
    if n_exact != 1:
        problems.append("the exact token line must occur exactly once, found %d" % n_exact)
    return problems


def check_build_exact(text, tag_jobs=BUILD_TAG_JOBS):
    """Problems of a build.yml text against the exact expressions (empty = fine): the one secret use is the
    exact token line; every upload step has exactly one `if:` and it is the tag condition; each job in
    `tag_jobs` exists and has exactly one job-level `if:`, the tag condition."""
    problems = secret_word_problems(text, BUILD_TOKEN_LINE)
    lines = text.splitlines()
    jobs = jobs_of(lines)
    if not jobs:
        return problems + ["no jobs found"]
    uploads = 0
    for job, (lo, hi) in jobs.items():
        for step in steps_of(lines, lo, hi):
            if not any("actions/upload-artifact" in l for l in step):
                continue
            uploads += 1
            conds = step_values(step, "if")
            if conds != [TAG_GUARD]:
                problems.append("job %s: the upload condition is %s, expected [%r]" % (job, conds, TAG_GUARD))
    if uploads == 0:
        problems.append("no upload-artifact step found")
    for job in tag_jobs:
        if job not in jobs:
            problems.append("job %s is missing" % job)
            continue
        lo, hi = jobs[job]
        conds = []
        for l in lines[lo:hi]:
            m = re.match(r"^    if:\s*(.*?)\s*$", l)
            if m:
                conds.append(m.group(1))
        if conds != [TAG_GUARD]:
            problems.append("job %s: the job condition is %s, expected [%r]" % (job, conds, TAG_GUARD))
    return problems


GOOD_BUILD = GOOD.replace(
    "  release:\n",
    "  flasher-assets:\n    if: startsWith(github.ref, 'refs/tags/v')\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n\n  release:\n")


def selftest_build_exact():
    good = GOOD_BUILD
    expect("build exact sample: the exact workflow has no problem", good != GOOD and check_build_exact(good) == [],
           str(check_build_exact(good)))

    def caught(name, mutated):
        expect("build exact sample %s" % name, mutated != good and check_build_exact(mutated) != [],
               str(check_build_exact(mutated)))
    caught("b5: a second use of the secret after the empty fallback is caught",
           good.replace("&& secrets.FRY_API_TOKEN || '' }}", "&& secrets.FRY_API_TOKEN || '' || secrets.FRY_API_TOKEN }}"))
    caught("b6: a token expression that a run without the tag satisfies is caught",
           good.replace("'refs/tags/v') && secrets.FRY_API_TOKEN", "'refs/tags/v') || secrets.FRY_API_TOKEN"))
    caught("b7: an upload condition that is always true is caught",
           good.replace("        if: startsWith(github.ref, 'refs/tags/v')\n        with:",
                        "        if: startsWith(github.ref, 'refs/tags/v') || true\n        with:"))
    caught("b8: an upload condition that another event satisfies is caught",
           good.replace("        if: startsWith(github.ref, 'refs/tags/v')\n        with:",
                        "        if: startsWith(github.ref, 'refs/tags/v') || github.event_name != 'push'\n        with:"))
    caught("b9: a release job condition that is always true is caught",
           good.replace("    needs: [build]\n    if: startsWith(github.ref, 'refs/tags/v')\n",
                        "    needs: [build]\n    if: startsWith(github.ref, 'refs/tags/v') || true\n"))
    caught("b9b: a flasher-assets job condition that is always true is caught",
           good.replace("  flasher-assets:\n    if: startsWith(github.ref, 'refs/tags/v')\n",
                        "  flasher-assets:\n    if: startsWith(github.ref, 'refs/tags/v') || true\n"))
    caught("b9c: a flasher-assets job without a condition is caught",
           good.replace("  flasher-assets:\n    if: startsWith(github.ref, 'refs/tags/v')\n", "  flasher-assets:\n"))
    caught("b9d: a release job without a condition is caught",
           good.replace("    needs: [build]\n    if: startsWith(github.ref, 'refs/tags/v')\n", "    needs: [build]\n"))
    caught("b10: an extra use of the secret in the index form is caught",
           good.replace("        run: pio run\n", "          LEAK: ${{ secrets['FRY_API_TOKEN'] }}\n        run: pio run\n"))
    caught("b11: an extra use of the secret in the dotted form is caught",
           good.replace("        run: pio run\n", "          LEAK: ${{ secrets.FRY_API_TOKEN }}\n        run: pio run\n"))
    caught("b12: the token line twice is caught",
           good.replace("        run: pio run\n", "          FRY_API_TOKEN: ${{ startsWith(github.ref, 'refs/tags/v') && secrets.FRY_API_TOKEN || '' }}\n        run: pio run\n"))
    caught("b13: a comment line with an expression that names the secret is caught",
           good.replace("        run: pio run\n", "        run: |\n          # ${{ secrets.FRY_API_TOKEN }}\n          pio run\n"))
    caught("b14: the whole secrets context is caught",
           good.replace("        run: pio run\n", "        run: echo ${{ toJSON(secrets) }}\n"))
    caught("b15: an extra job that passes every secret on is caught",
           good + "\n  call:\n    uses: ./.github/workflows/other.yml\n    secrets: inherit\n")
    caught("b16: an upload step with a second if: is caught",
           good.replace("        if: startsWith(github.ref, 'refs/tags/v')\n        with:",
                        "        if: startsWith(github.ref, 'refs/tags/v')\n        if: true\n        with:"))
    caught("b17: a workflow without the flasher-assets job is caught", good.replace("  flasher-assets:\n", "  flasher-other:\n"))
    commented = good.replace("jobs:\n", "# the token is read as secrets.FRY_API_TOKEN below\njobs:\n")
    expect("build exact sample: a plain comment that names the secrets context is not a use",
           commented != good and check_build_exact(commented) == [], str(check_build_exact(commented)))
    expect("build exact sample: a workflow without jobs is rejected", check_build_exact("name: x\n") != [])


def selftest_secret_words_fault():
    good = GOOD_FAULT.replace("type: boolean", "type: boolean\n        default: false")
    expect("fault secrets sample: the exact workflow has no problem", good != GOOD_FAULT and secret_word_problems(good, FAULT_TOKEN_LINE) == [],
           str(secret_word_problems(good, FAULT_TOKEN_LINE)))

    def caught(name, mutated):
        expect("fault secrets sample %s" % name, mutated != good and secret_word_problems(mutated, FAULT_TOKEN_LINE) != [],
               str(secret_word_problems(mutated, FAULT_TOKEN_LINE)))
    caught("x13: a second use in the dotted form is caught",
           good.replace("        run: pio run -e esp32s3\n", "        run: pio run -e esp32s3\n      - run: echo ${{ secrets.OTHER_VALUE }}\n"))
    caught("x14: a second use in the index form is caught",
           good.replace("        run: pio run -e esp32s3\n", "        run: pio run -e esp32s3\n      - run: echo ${{ secrets['OTHER_VALUE'] }}\n"))
    caught("x15: the whole secrets context is caught",
           good.replace("        run: pio run -e esp32s3\n", "        run: pio run -e esp32s3\n      - run: echo ${{ toJSON(secrets) }}\n"))
    caught("x16: an extra job that passes every secret on is caught",
           good + "\n  call:\n    uses: ./.github/workflows/build.yml\n    secrets: inherit\n")
    caught("x19: the token line twice is caught",
           good.replace("        run: pio run -e esp32s3\n", "          FRY_API_TOKEN: ${{ inputs.with_token && startsWith(github.ref, 'refs/tags/v') && secrets.FRY_API_TOKEN || '' }}\n        run: pio run -e esp32s3\n"))
    expect("fault secrets sample: a workflow with no token line is caught", secret_word_problems("name: x\n", FAULT_TOKEN_LINE) != [])


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
    selftest_fault_exact()
    with open(fault_path) as f:
        exact_problems = check_fault_exact(f.read())
    expect("fault-images workflow file: the exact token line and the exact upload condition",
           exact_problems == [], "\n      " + "\n      ".join(exact_problems))
    selftest_build_exact()
    build_exact_problems = check_build_exact(text)
    expect("workflow file: the exact token line, the exact upload condition and the exact job conditions",
           build_exact_problems == [], "\n      " + "\n      ".join(build_exact_problems))
    selftest_secret_words_fault()
    with open(fault_path) as f:
        word_problems = secret_word_problems(f.read(), FAULT_TOKEN_LINE)
    expect("fault-images workflow file: the word secrets appears only in the exact token line",
           word_problems == [], "\n      " + "\n      ".join(word_problems))
    print("%d passed, %d failed" % (passed, failed))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
