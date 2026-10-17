luna-authmanager test and hardening harness
===========================================

Three layers: unit tests on the build host, the sanitizers and valgrind over
them, and static analysis and a warning gate over the sources.

Every script takes a recipe workdir of a Yocto build
(`tmp/work/<arch>/<recipe>/1.0.0+git`) for the toolchain and the sysroot.
Any recipe whose sysroot has glib, luna-service2, json-c, libxcrypt, Qt 6
Core and gtest will do; the corei7-64 one is the one the host can run.

Unit tests (`unit/`, `fakes/`)
------------------------------

gtest, built from the daemon's own objects (the `authmanager-core` object
library, everything but `main()` and `Src/Platform.cpp`) and linked with
stand-ins instead of what the device has:

- `fakes/fakebus.cpp`: luna-service2, in process. It records every call
  and reply; a test answers calls as db8 or storaged would
  (`fakebus::reply`), and calls the daemon's methods as a client
  (`callMethod`). The test binary does not link libluna-service2.
- `fakes/fakeplatform.cpp`: `Src/Platform.h`. The data directory is a
  fresh directory per test, and the monotonic clock only moves when a test
  moves it (`fakeplatform::advanceMs`), so lockouts are tested without
  waiting.

Each test starts the singletons as `Src/Main.cpp` does and plays db8's side
of the start-up (`boot()`).

| File | What it pins |
|---|---|
| `test_passcode.cpp` | the version 2 file (yescrypt, salted, 0600); hashes starting with NUL no longer matching each other; luna-sysmgr's format matched and moved to version 2; the strength rules; unknown lock modes; save failures (unwritable directory, a short write) leaving the old passcode; a stale temporary file or link not followed |
| `test_lockout.cpp` | five free tries, then 30 s doubling to an hour; the right code refused while locked out; the count reset by a right or new passcode; the lockout under a policy without a retry limit |
| `test_policy.cpp` | a db8 error not taken for "no device policy"; `results` that is not an array; one device-policy put at a time; the watch cancelled when it fires or fails; negative policy values clamped; retries kept from the device record; the wipe after the last EAS retry; policy rules on top of the baseline |
| `test_methods.cpp` | malformed requests refused; both bus names; hostile payloads; the ACG files: the passcode methods only in `auth.passcode` (and matching alone in `auth.verify`), and the keymanager name allowed to call storaged's wipe |

Build and run on the host:

    cmake -DBUILD_TESTING=ON ...      # with the recipe's toolchain.cmake
    ninja authmanager-tests
    <sysroot>/usr/lib/ld-linux-x86-64.so.2 --library-path <sysroot>/usr/lib \
        tests/authmanager-tests

Hardening (`hardening/`)
------------------------

- `run-sanitizers.sh <corei7-64 workdir>`: the tests under ASan+UBSan and
  TSan, each with gcc and with clang, and under valgrind memcheck on the image
  toolchain's own build. The image toolchain ships no sanitizer runtimes, so
  the host's gcc and clang build against the sysroot (`host-sysroot.cmake`);
  the host's glibc is the sysroot's.
- `static-analysis.sh <corei7-64 workdir>`: gcc `-fanalyzer` at -O0 and -O2,
  the clang analyzer with the alpha checkers, clang-tidy, cppcheck
  (exhaustive), flawfinder and Coccinelle (`cocci/`). It fails on any finding
  not in `baseline.txt`, where each entry that was looked at and left has its
  reason. cppcheck's style notes are listed but do not gate. sparse is not
  run: it parses C only.
- `build-all.py <workdir>...`: the warning gate. The daemon and the tests
  built for each architecture given, with the image's gcc and with the host's
  clang, `-Wall -Wextra` under the project's flags; a warning in `Src/` or
  `tests/` fails it. Run it with the armv7, aarch64 and corei7-64 workdirs.

Not covered here
----------------

The tests run on x86-64 only: the armv7 and aarch64 builds are compiled by
`build-all.py` but not run. The ACG tests read the files; that ls-hubd
enforces them, and the cost of a yescrypt hash on the slowest device, can
only be seen on a device.
