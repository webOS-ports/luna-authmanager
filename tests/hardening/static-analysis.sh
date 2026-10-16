#!/bin/sh
# Copyright (c) 2026 Herman van Hazendonk <github.com@herrie.org>
#
# SPDX-License-Identifier: Apache-2.0
#
# static-analysis.sh <corei7-64 recipe workdir> [work dir]
#
# Static-analysis gate for the daemon's sources (Src/). Runs:
#
#   gcc -fanalyzer -O0, -O2  use after free, double free, leaks, NULL
#                            dereference, uninitialised reads; twice, as
#                            inlining at -O2 hides some paths and shows others
#   clang analyzer           the same from a second engine, with the alpha
#                            unix/security/core checkers
#   clang-tidy               clang-analyzer-*, bugprone-*, cert-*, ...
#   cppcheck                 all checks, exhaustive, inconclusive
#   flawfinder               race-prone calls (TOCTOU), unsafe string calls
#   Coccinelle               tests/hardening/cocci/*.cocci: a bus field
#                            compared, or made a std::string, without a NULL
#                            check; a g_strdup_printf() passed on and leaked
#
# sparse is not run: it parses C only, and the daemon is C++.
#
# Findings are compared with tests/hardening/baseline.txt, the triaged ones
# that are not this daemon's to fix or are false positives (each with its
# reason). Anything else fails the gate. A tool that is not installed is
# reported and skipped, not passed.
set -u
export LC_ALL=C

W=${1:?usage: static-analysis.sh <corei7-64 recipe workdir> [work dir]}
WORK=${2:-${XDG_CACHE_HOME:-$HOME/.cache}/luna-authmanager/analysis}
SRC=$(cd "$(dirname "$0")/../.." && pwd)
HERE=$SRC/tests/hardening
S=$W/recipe-sysroot
N=$W/recipe-sysroot-native
B=$WORK/build
mkdir -p "$WORK"
skipped=""

export PKG_CONFIG_SYSROOT_DIR=$S
export PKG_CONFIG_LIBDIR=$S/usr/lib/pkgconfig:$S/usr/share/pkgconfig
export PKG_CONFIG_PATH=$S/usr/lib/pkgconfig

# A configured tree for the include paths and defines (moc output included).
gccdir=$(ls -d "$S"/usr/lib/x86_64-*-linux/* | head -n 1)
triple=$(basename "$(dirname "$gccdir")")
cxxinc=$S/usr/include/c++/$(basename "$gccdir")
PATH=$N/usr/bin:$PATH cmake -S "$SRC" -B "$B" -G Ninja \
	-DCMAKE_TOOLCHAIN_FILE="$HERE/host-sysroot.cmake" -DDM_SYSROOT="$S" -DDM_HOST_CC=gcc \
	-DQT_HOST_PATH="$N/usr" -DCMAKE_CXX_STANDARD=17 -DWEBOS_INSTALL_ROOT=/ \
	-DCMAKE_POLICY_VERSION_MINIMUM=3.5 -DCMAKE_EXPORT_COMPILE_COMMANDS=ON \
	>"$WORK/configure.log" 2>&1 || { echo "configure failed, see $WORK/configure.log"; exit 2; }

# The flags the build uses for a source file, without the output options.
flags() {
	python3 - "$B/compile_commands.json" "$1" <<'EOF'
import json, shlex, sys
db, src = sys.argv[1], sys.argv[2]
for e in json.load(open(db)):
    if e["file"].endswith(src):
        args = shlex.split(e["command"])[1:]
        out, skip = [], False
        for a in args:
            if skip: skip = False; continue
            if a in ("-o", "-c", "-MF", "-MT", "-MQ"): skip = True; continue
            if a.endswith(src) or a.startswith("-M"): continue
            out.append(a)
        print(" ".join(shlex.quote(a) for a in out))
        break
EOF
}

SOURCES=$(cd "$SRC" && ls Src/*.cpp)
: >"$WORK/findings.txt"

record() {
	# tool, then findings on stdin, one per line, as "file:line: text"
	sed -e "s|$SRC/||g" -e "s|^|$1: |" >>"$WORK/findings.txt"
}

have() {
	command -v "$1" >/dev/null 2>&1 && return 0
	skipped="$skipped $1"
	echo "== $1: not installed, skipped"
	return 1
}

if have gcc; then
	for opt in -O0 -O2; do
		echo "== gcc -fanalyzer $opt"
		for f in $SOURCES; do
			eval "gcc -x c++ -c -o /dev/null $opt -fanalyzer -Wanalyzer-too-complex \
				--param=analyzer-bb-explosion-factor=50 --param=analyzer-max-enodes-per-program-point=64 \
				$(flags "$f") $SRC/$f" 2>&1
		done | grep -E "^$SRC/Src/[^:]+:[0-9]+:[0-9]+: warning: .*\[-Wanalyzer" \
			| sed -E 's/terminating analysis for this program point:.*\[-Wanalyzer-too-complex\]/terminating analysis (too complex) [-Wanalyzer-too-complex]/' \
			| sort -u | record "gcc-fanalyzer$opt"
	done
fi

if have clang; then
	echo "== clang analyzer"
	for f in $SOURCES; do
		eval "clang++ --analyze -Xanalyzer -analyzer-output=text \
			-Xanalyzer -analyzer-checker=core,cplusplus,unix,deadcode,security,nullability,optin.portability,optin.core \
			-Xanalyzer -analyzer-checker=alpha.unix,alpha.security,alpha.core.PointerArithm,alpha.core.CastSize,alpha.core.Conversion,alpha.cplusplus \
			--gcc-install-dir=$gccdir -isystem $cxxinc -isystem $cxxinc/$triple \
			$(flags "$f" | sed 's/-fpermissive//; s/-fcanon-prefix-map//') -o /dev/null $SRC/$f" 2>&1
	done | grep -E "^$SRC/Src/[^:]+:[0-9]+:[0-9]+: warning:" \
		| sed -E 's/:[0-9]+: warning:/: warning:/' | sort -u | record clang-analyzer
fi

if have clang-tidy; then
	echo "== clang-tidy"
	for f in $SOURCES; do
		clang-tidy --quiet -p "$B" "$SRC/$f" \
			--checks='clang-analyzer-*,bugprone-*,cert-*,concurrency-*,misc-*,performance-*,portability-*,-bugprone-easily-swappable-parameters,-misc-include-cleaner,-misc-unused-parameters,-misc-non-private-member-variables-in-classes,-misc-use-anonymous-namespace,-misc-use-internal-linkage,-cert-err33-c,-bugprone-assignment-in-if-condition,-clang-analyzer-security.insecureAPI.DeprecatedOrUnsafeBufferHandling,-bugprone-reserved-identifier,-cert-dcl37-c,-cert-dcl51-cpp,-bugprone-macro-parentheses,-bugprone-branch-clone,-bugprone-narrowing-conversions,-bugprone-implicit-widening-of-multiplication-result,-cert-dcl58-cpp,-misc-const-correctness,-bugprone-switch-missing-default-case,-cert-err58-cpp,-cert-oop54-cpp,-performance-enum-size' \
			--extra-arg="--gcc-install-dir=$gccdir" --extra-arg="-isystem$cxxinc" --extra-arg="-isystem$cxxinc/$triple" \
			--extra-arg=-Wno-unknown-warning-option 2>/dev/null
	done | grep -E "^$SRC/Src/[^:]+:[0-9]+:[0-9]+: (warning|error):" \
		| sed -E 's/:[0-9]+: (warning|error):/: \1:/' | sort -u | record clang-tidy
fi

if have cppcheck; then
	echo "== cppcheck"
	cppcheck --enable=all --check-level=exhaustive --inconclusive --std=c++17 --language=c++ \
		--library=gnu --library=posix --library=qt --force --inline-suppr --quiet \
		--suppress=missingIncludeSystem --suppress=missingInclude --suppress=unmatchedSuppression \
		--suppress=checkersReport --suppress=unusedFunction --suppress=normalCheckLevelMaxBranches \
		--template='{file}:{line}: {severity}: {message} [{id}]' \
		-I "$SRC/Src" -DQT_NO_KEYWORDS -D__linux__ -D__GNUC__ \
		$(cd "$SRC" && printf '%s ' $SOURCES | sed "s|Src/|$SRC/Src/|g") \
		>"$WORK/cppcheck.log" 2>&1
	# Style findings (naming, const-ness, override, C casts) are listed for
	# reading but do not gate; the bug classes do.
	grep -E "^$SRC/Src/[^:]+:[0-9]+: style:" "$WORK/cppcheck.log" | sed "s|$SRC/||" | sort -u >"$WORK/cppcheck-style.txt"
	grep -E "^$SRC/Src/[^:]+:[0-9]+: (error|warning|performance|portability):" "$WORK/cppcheck.log" \
		| sort -u | record cppcheck
	# ...except the style checks that point at logic errors.
	grep -E "\[(knownConditionTrueFalse|redundantAssignment|duplicateCondition|identicalConditionAfterEarlyExit|oppositeInnerCondition|duplicateBranch|uninitvar|nullPointer.*)\]$" \
		"$WORK/cppcheck-style.txt" | sed "s|^|$SRC/|" | record cppcheck
fi

if have flawfinder; then
	echo "== flawfinder"
	flawfinder --minlevel=1 --falsepositive --dataonly --quiet "$SRC/Src" 2>&1 \
		| grep -E "^$SRC/Src/[^:]+:[0-9]+: +\[[1-5]\]" | sort -u | record flawfinder
fi

if have spatch; then
	echo "== Coccinelle"
	for c in "$HERE"/cocci/*.cocci; do
		spatch --very-quiet --c++ --sp-file "$c" --dir "$SRC/Src" 2>/dev/null \
			| awk -v rule="$(basename "$c" .cocci)" '
				/^\+\+\+ / { file = $2 }
				/^@@ / { split($2, a, ","); line = -a[1]; n = 0; next }
				/^-/ && !/^---/ { print file ":" line + n ": " rule ": " substr($0, 2); n++; next }
				/^ / { n++ }' \
			| sed -e "s|/tmp/nothing/|Src/|" -e "s|$SRC/||"
	done | sort -u | record coccinelle
fi

# Line numbers move; a baseline entry is tool, file and message.
key() { sed -E 's/^([^:]+): ([^:]+):[0-9]+(:[0-9]+)?:/\1: \2:/'; }
grep -v '^#' "$HERE/baseline.txt" 2>/dev/null | sed 's/ *#.*//' | grep . | key | sort -u >"$WORK/baseline.keys"
key <"$WORK/findings.txt" | sort -u >"$WORK/findings.keys"
comm -23 "$WORK/findings.keys" "$WORK/baseline.keys" >"$WORK/new.keys"
comm -13 "$WORK/findings.keys" "$WORK/baseline.keys" >"$WORK/gone.keys"

echo
[ -s "$WORK/cppcheck-style.txt" ] && echo "cppcheck style notes (not gated): $(wc -l <"$WORK/cppcheck-style.txt"), in $WORK/cppcheck-style.txt"
echo "findings: $(wc -l <"$WORK/findings.keys"), triaged in baseline.txt: $(wc -l <"$WORK/baseline.keys")"
if [ -s "$WORK/gone.keys" ]; then
	echo "no longer reported (drop from baseline.txt):"
	sed 's/^/  /' "$WORK/gone.keys"
fi
[ -n "$skipped" ] && echo "skipped:$skipped"
if [ -s "$WORK/new.keys" ]; then
	echo "NEW findings:"
	sed 's/^/  /' "$WORK/new.keys"
	exit 1
fi
echo "clean"
exit 0
