#!/usr/bin/env python3
# Copyright (c) 2026 Herman van Hazendonk <github.com@herrie.org>
#
# SPDX-License-Identifier: Apache-2.0
#
# build-all.py [--work DIR] <recipe workdir>...
#
# The warning gate: the daemon and its tests built for every architecture
# given (one luna-authmanager recipe workdir each, e.g. the armv7, aarch64
# and corei7-64 ones under tmp/work), with both compilers:
#
#   gcc    the image toolchain itself, through the recipe's toolchain.cmake
#   clang  the build host's clang++, --target=<the toolchain's triple>, on
#          the same compile commands against the same sysroot
#
# Both with -Wall -Wextra under the project's flags (its -Wno-* stay). A warning in Src/ or
# tests/ fails the gate; one from a header in the sysroot is listed (it is
# not ours to fix) but does not.
#
# armv7 is in the list for a reason: it is the 32-bit target, where size_t,
# long and the like are narrower than on the other two.

import argparse, collections, glob, json, os, re, shlex, subprocess, sys

ap = argparse.ArgumentParser()
ap.add_argument("--work", default=os.path.join(os.environ.get("XDG_CACHE_HOME") or os.path.expanduser("~/.cache"), "luna-authmanager", "builds"))
ap.add_argument("workdirs", nargs="+")
opts = ap.parse_args()

SRC = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
WARN = re.compile(r"^(?P<file>[^\s:]+):(?P<line>\d+):\d+: warning: (?P<msg>.*)$", re.M)
# Flags only gcc knows; clang would warn about each, which is noise.
GCC_ONLY = ("-fcanon-prefix-map", "-mthumb-interwork", "-fno-tree-vrp", "-fmacro-prefix-map",
            "-fdebug-prefix-map", "-ffile-prefix-map")
EXTRA = ["-Wall", "-Wextra"]


def classify(text):
    ours, theirs = collections.Counter(), collections.Counter()
    for m in WARN.finditer(text):
        f = os.path.realpath(m["file"]) if os.path.exists(m["file"]) else m["file"]
        key = "%s:%s: %s" % (f.replace(SRC + "/", ""), m["line"], m["msg"])
        (ours if f.startswith(SRC + "/") else theirs)[key] += 1
    return ours, theirs


def run(cmd, **kw):
    return subprocess.run(cmd, capture_output=True, text=True, **kw)


def native_path(w):
    n = os.path.join(w, "recipe-sysroot-native")
    t = sorted(glob.glob(os.path.join(n, "usr/bin/*-webos-linux*")))
    return os.pathsep.join(t[:1] + [os.path.join(n, "usr/bin"), os.path.join(n, "bin"), os.environ["PATH"]])


results = []
fail = False
for w in opts.workdirs:
    w = os.path.abspath(w)
    arch = os.path.basename(os.path.dirname(os.path.dirname(w)))
    sysroot = os.path.join(w, "recipe-sysroot")
    env = dict(os.environ, PATH=native_path(w), PKG_CONFIG_SYSROOT_DIR=sysroot,
               PKG_CONFIG_LIBDIR=sysroot + "/usr/lib/pkgconfig:" + sysroot + "/usr/share/pkgconfig",
               PKG_CONFIG_PATH=sysroot + "/usr/lib/pkgconfig")
    bd = os.path.join(opts.work, arch)

    # gcc: a full build, daemon and tests.
    cfg = run(["cmake", "-S", SRC, "-B", bd, "-G", "Ninja",
               "-DCMAKE_TOOLCHAIN_FILE=" + os.path.join(w, "toolchain.cmake"),
               "-DQT_HOST_PATH=" + os.path.join(w, "recipe-sysroot-native/usr"),
               "-DCMAKE_CXX_STANDARD=17", "-DWEBOS_INSTALL_ROOT=/", "-DCMAKE_POLICY_VERSION_MINIMUM=3.5",
               "-DCMAKE_EXPORT_COMPILE_COMMANDS=ON", "-DBUILD_TESTING=ON",
               "-DCMAKE_CXX_FLAGS_RELEASE=" + " ".join(EXTRA), "-DCMAKE_BUILD_TYPE=Release"], env=env)
    if cfg.returncode:
        print("FAIL configure %s\n%s" % (arch, cfg.stdout[-3000:] + cfg.stderr[-3000:]))
        fail = True
        continue
    run(["ninja", "-C", bd, "-t", "clean"], env=env)
    b = run(["ninja", "-C", bd, "LunaAuthManager", "authmanager-tests"], env=env)
    ours, theirs = classify(b.stdout + b.stderr)
    ok = b.returncode == 0
    results.append((arch, "gcc", ok, ours, theirs))
    if not ok:
        print("FAIL build %s gcc\n%s" % (arch, "\n".join(l for l in b.stdout.splitlines() if "error" in l)[:4000]))

    # clang: the same compile commands with the host's clang++.
    db = json.load(open(os.path.join(bd, "compile_commands.json")))
    cxx = shlex.split(db[0]["command"])[0]
    triple = os.path.basename(cxx)[: -len("-g++")]
    # clang does not take the "webos" vendor for a gcc layout it knows, so
    # it is shown where the sysroot's gcc and libstdc++ headers are.
    gccdir = sorted(glob.glob(os.path.join(sysroot, "usr/lib", triple, "*")))[-1]
    cxxinc = os.path.join(sysroot, "usr/include/c++", os.path.basename(gccdir))
    clang_extra = ["--gcc-install-dir=" + gccdir, "-isystem", cxxinc,
                   "-isystem", os.path.join(cxxinc, triple)]
    out, ok = "", True
    for e in db:
        args = shlex.split(e["command"])
        # -Wall -Wextra first, so the project's own -Wno-* (unused parameters
        # and variables, member order) win as they do with gcc, where an
        # explicit -Wno-* beats -Wextra wherever it stands.
        # (The gcc build's own copy of them, at the end of the command, goes.)
        args = ["clang++", "--target=" + triple] + EXTRA + [
            a for a in args[1:] if not a.startswith(GCC_ONLY) and a not in EXTRA]
        i = args.index("-o")
        args[i + 1] = "/dev/null"
        args += clang_extra + ["-Wno-unknown-warning-option", "-Wno-unused-command-line-argument"]
        r = run(args, cwd=e["directory"], env=env)
        out += r.stderr
        if r.returncode:
            ok = False
            print("FAIL clang %s %s\n%s" % (arch, e["file"], r.stderr[-2000:]))
    ours, theirs = classify(out)
    results.append((arch, "clang", ok, ours, theirs))

print()
for arch, cc, ok, ours, theirs in results:
    state = "ok" if ok else "BUILD FAILED"
    print("%-50s %-5s %s, our warnings: %d, sysroot headers: %d" % (arch, cc, state, len(ours), len(theirs)))
    for k in sorted(ours):
        print("    " + k)
    for k in sorted(theirs):
        print("    (header) " + k)
    if not ok or ours:
        fail = True
sys.exit(1 if fail else 0)
