#!/usr/bin/env python3
"""Work out which integration test targets a change adds or modifies.

Used by the `PR Integration Tests` job in .github/workflows/ci.yml (#575).
The full suite (`cargo test --workspace --all-features`) takes 20+ minutes
and only runs after merge (tests.yml); this runs the targets a PR's own
diff touches, so the test that proves a fix runs before the fix merges.

Usage:
    scripts/pr-integration-tests.py BASE [HEAD]          # print the plan
    scripts/pr-integration-tests.py BASE [HEAD] --run    # ... and run it

BASE and HEAD are any git revisions; the diff is BASE...HEAD (changes on
HEAD since the merge base), as GitHub shows a PR. HEAD defaults to HEAD.
Locally: `scripts/pr-integration-tests.py origin/main`.

Targets come from `cargo metadata`, not from guessing at paths, so package
names (crates/proxy is `zentinel-proxy`), `[[test]] name`/`path` overrides
and `autotests = false` are cargo's own answer. A changed file selects:

  - the test target whose source root it is (tests/foo.rs, tests/foo/main.rs,
    or whatever path a `[[test]]` section names);
  - the target tests/<dir>/main.rs, for any other file under tests/<dir>/;
  - every test target of its package, for any other file under tests/
    (a shared helper such as tests/common/mod.rs, which each target that
    uses it pulls in with `mod common;`).

A changed member Cargo.toml additionally selects every test target that is
new or different (name, path, required-features) compared with the base.

Crates in the workspace `exclude` list are not in `cargo metadata` and are
reported as skipped: ci.yml's `Excluded Crates` job already runs
`cargo test --all-targets` for sim and config-inspect on every PR.

Exit status: 0 when the plan is empty (nothing to run is a success) or all
selected tests pass; non-zero if planning fails or a test fails.
"""

import json
import os
import subprocess
import sys
import tempfile
from collections import OrderedDict


def git(*args, cwd=None):
    return subprocess.run(
        ["git", *args], cwd=cwd, check=True, capture_output=True, text=True
    ).stdout


def metadata(root):
    """Workspace members and their test targets, with repo-relative paths."""
    out = subprocess.run(
        ["cargo", "metadata", "--no-deps", "--format-version", "1", "--offline"],
        cwd=root, check=True, capture_output=True, text=True,
    ).stdout
    meta = json.loads(out)
    ws_root = meta["workspace_root"]
    members = set(meta["workspace_members"])
    packages = []
    for pkg in meta["packages"]:
        if pkg["id"] not in members:
            continue
        pkg_dir = os.path.relpath(os.path.dirname(pkg["manifest_path"]), ws_root)
        tests = [
            {
                "name": t["name"],
                "path": os.path.relpath(t["src_path"], ws_root),
                "required_features": sorted(t.get("required-features", [])),
            }
            for t in pkg["targets"]
            if "test" in t["kind"]
        ]
        packages.append({"name": pkg["name"], "dir": pkg_dir, "tests": tests})
    return packages


def metadata_at(rev):
    """metadata() for a revision other than the checkout, via a scratch worktree."""
    with tempfile.TemporaryDirectory() as tmp:
        wt = os.path.join(tmp, "tree")
        git("worktree", "add", "--detach", "--quiet", wt, rev)
        try:
            return metadata(wt)
        finally:
            git("worktree", "remove", "--force", wt)


def excluded_dirs(root):
    """The workspace `exclude` list, read from the root manifest.

    A minimal scan instead of a TOML parser: CI's python has tomllib, but
    python 3.9 (macOS system python) does not, and the list is plain strings.
    """
    dirs, inside = [], False
    with open(os.path.join(root, "Cargo.toml")) as f:
        for line in f:
            s = line.split("#", 1)[0].strip()
            if s.startswith("exclude") and "[" in s:
                inside = True
                s = s.split("[", 1)[1]
            if inside:
                for part in s.replace("]", ",").split(","):
                    part = part.strip().strip('"').strip("'")
                    if part:
                        dirs.append(part.rstrip("/"))
                if "]" in s:
                    break
    return dirs


def under(path, directory):
    return directory == "." or path == directory or path.startswith(directory + "/")


def main(argv):
    run = "--run" in argv
    args = [a for a in argv if a != "--run"]
    if not 1 <= len(args) <= 2:
        print(__doc__, file=sys.stderr)
        return 2
    base, head = args[0], args[1] if len(args) == 2 else "HEAD"

    root = git("rev-parse", "--show-toplevel").strip()
    merge_base = git("merge-base", base, head).strip()
    # A/M/R: a deleted test file has nothing left to run. Renames are
    # reported under their new path.
    changed = [
        p for p in git(
            "diff", "--name-only", "--diff-filter=AMR", f"{merge_base}...{head}"
        ).splitlines() if p
    ]

    at_head = git("rev-parse", head).strip() == git("rev-parse", "HEAD").strip()
    if run and not at_head:
        # cargo test builds the working tree, so it must be HEAD.
        print(f"error: --run needs {head} checked out", file=sys.stderr)
        return 2

    packages = metadata(root) if at_head else metadata_at(head)
    excluded = excluded_dirs(root)

    plan = OrderedDict()  # package -> OrderedDict(target -> [reasons])
    notes = []

    def select(pkg, target, reason):
        plan.setdefault(pkg["name"], OrderedDict()).setdefault(target, []).append(reason)

    def owner(path):
        matches = [p for p in packages if under(path, p["dir"])]
        return max(matches, key=lambda p: len(p["dir"])) if matches else None

    for path in changed:
        excl = next((d for d in excluded if under(path, d)), None)
        if excl:
            if "/tests/" in "/" + os.path.relpath(path, excl):
                notes.append(f"skip {path}: {excl} is excluded from the workspace "
                             "(covered by the Excluded Crates job)")
            continue
        pkg = owner(path)
        if pkg is None:
            continue
        by_path = {t["path"]: t for t in pkg["tests"]}
        if path in by_path:
            select(pkg, by_path[path]["name"], f"{path} changed")
            continue
        tests_dir = os.path.join(pkg["dir"], "tests") if pkg["dir"] != "." else "tests"
        if not under(path, tests_dir) or not path.endswith(".rs"):
            continue
        sub = os.path.relpath(path, tests_dir).split("/")
        main_rs = os.path.join(tests_dir, sub[0], "main.rs")
        if len(sub) > 1 and main_rs in by_path:
            select(pkg, by_path[main_rs]["name"], f"{path} changed (part of {main_rs})")
        elif pkg["tests"]:
            for t in pkg["tests"]:
                select(pkg, t["name"], f"helper {path} changed")
        else:
            notes.append(f"skip {path}: {pkg['name']} declares no test targets")

    manifests = {os.path.join(p["dir"], "Cargo.toml"): p for p in packages}
    changed_manifests = [m for m in changed if m in manifests]
    if changed_manifests:
        # Compare with the base's declared targets: a new or re-pointed
        # `[[test]]` (or `autotests` switched on) is a test the PR adds.
        base_pkgs = {p["name"]: p for p in metadata_at(merge_base)}
        for m in changed_manifests:
            pkg = manifests[m]
            old = base_pkgs.get(pkg["name"], {"tests": []})["tests"]
            for t in pkg["tests"]:
                if t not in old:
                    select(pkg, t["name"], f"{m}: test target is new or changed")

    print(f"Integration tests for {merge_base[:12]}...{head} "
          f"({len(changed)} changed file(s))")
    for n in notes:
        print(f"  {n}")
    if not plan:
        print("No integration test target was added or changed: nothing to run.")
        if os.environ.get("GITHUB_ACTIONS"):
            print("::notice title=PR Integration Tests::"
                  "No integration test target was added or changed; nothing to run.")
    commands = []
    for name, targets in plan.items():
        for target, reasons in targets.items():
            print(f"  {name} --test {target}")
            for r in reasons:
                print(f"      <- {r}")
        # --all-features: same as tests.yml, which runs these targets after merge.
        cmd = ["cargo", "test", "--all-features", "-p", name]
        for target in targets:
            cmd += ["--test", target]
        commands.append(cmd)
    if commands:
        print("Plan:")
    for cmd in commands:
        print("  " + " ".join(cmd))

    out = os.environ.get("GITHUB_OUTPUT")
    if out:
        with open(out, "a") as f:
            f.write(f"targets={sum(len(t) for t in plan.values())}\n")

    if run:
        failed = []
        for cmd in commands:
            print("+ " + " ".join(cmd), flush=True)
            if subprocess.run(cmd, cwd=root).returncode != 0:
                failed.append(" ".join(cmd))
        if failed:
            for f in failed:
                print(f"FAILED: {f}", file=sys.stderr)
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
