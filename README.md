luna-authmanager
================

Summary
-------
The LuneOS authentication manager: device lock modes, EAS policy, retry and lockout state

The LuneOS authentication manager: device lock modes (PIN, password,
pattern, and "face" for a future adapter), Exchange ActiveSync policy
enforcement, retry/lockout state, keymanager unlock, and device wipe on
retry exhaustion.

Bus names
---------

* `com.palm.systemmanager` — the name every existing caller knows:
  cardshell's lock screens, the Settings screen-lock page, the phone PIN
  cards, the Enyo 1 authlib. Kept so the split from luna-sysmgr needs no
  flag day. Only the four authentication methods survive under it; the
  window-server, WebAppMgr and modal-dialog methods it once carried died
  with luna-sysmgr.
* `com.palm.systemmanager-keymanager` — companion handle used to talk to
  `com.palm.keymanager`.
* `com.webos.service.auth` — the modern alias, and where biometric
  orchestration (com.webos.service.fingerprint, a future face adapter)
  should land, folded into the same retry and lockout budget the passcode
  uses.

API
---

* `setDevicePasscode` — `{"lockMode": "none"|"pin"|"password"|"pattern"|"face", "passCode": string,
  "currentPasscode": string}` → `{returnValue}`, or `{returnValue: false, errorCode, errorText}`.
  `currentPasscode` is required whenever a passcode is set, except while an
  EAS policy that requires a password is pending (which also refuses
  `"none"`, so it can replace the passcode but not remove it). A wrong one
  is a wrong try like any other: errorCode -12, with `lockedOut`,
  `retriesLeft` and `lockoutSeconds`.
* `matchDevicePasscode` — `{"passCode": string}` → `{returnValue, unlockToken, tokenLifetime}`
  on a match, `{returnValue: false, lockedOut, retriesLeft, lockoutSeconds}` otherwise
* `getDeviceLockMode` — subscribable → `{lockMode, policyState, retriesLeft, policyRequiresPassword,
  biometricAllowed}`
* `getSecurityPolicy` — aggregate EAS policy and status

On `com.webos.service.auth` only, each also checking its caller by name:

* `consumeUnlockToken` — `{"token", "requester", "purpose": "unlock"|"enroll"}` → `{returnValue, valid}`.
  `"unlock"` for `com.palm.display` alone, `"enroll"` for
  `com.webos.service.faceunlock` and `com.webos.service.fingerprint`.
* `issueBiometricToken` — `{"factor": "face"|"fingerprint", "requester"}` → `{returnValue, unlockToken}`,
  or errorCode -13 with `passcodeRequired`. For the factor's own service.
* `reportBiometricFailure` — `{"factor"}` → `{returnValue, biometricAllowed}`. For the factor's own service.

### Unlock tokens

A right passcode earns a token: 128 random bits as 32 hex digits, bound to
the bus name that asked, good for 30 seconds and spent the first time it is
presented, honoured or not. One is outstanding at a time, and a new
passcode voids it. The lock screen hands it to
`com.palm.display/control/setLockStatus`, which spends it here before it
unlocks; Settings hands one to a biometric service to enrol a finger or a
face. A biometric match earns a token for unlocking only.

### Biometrics

A finger or a face may unlock only once the passcode has been entered (or
set) since this boot, within 72 hours of the last time it was, outside a
passcode lockout, and before five rejected biometric tries in a row; after
those it takes the passcode again. The biometric services report each
rejection here, so there is one budget, not one per screen wake.

Who may call them is set by ACG groups (`files/sysbus`):

* `auth.passcode` — `setDevicePasscode` and `matchDevicePasscode`, on both
  names. Held by the lock screen (`com.webos.surfacemanager-cardshell`,
  granted in this package's perm file), and asked for in their appinfo by
  the Settings screen-lock page and the email app (whose Enyo authlib asks
  for a device PIN when an Exchange policy needs one). Nothing else: an app
  that may set the passcode may also clear it.
* `auth.verify` — `matchDevicePasscode` on `com.webos.service.auth`, and
  nothing else: for an app that lets its user in with the screen lock
  passcode (the Authenticator's lock) without being able to set or clear
  it. Its tries count with the lock screen's and share their lockout.
* `auth.query` and `luna-sysmgr.operation` — the two read-only methods.
* `auth.unlocktoken` — `consumeUnlockToken`; granted to `com.palm.display`
  and the biometric services in their own perm files.
* `auth.biometric` — `issueBiometricToken` and `reportBiometricFailure`;
  granted to the biometric services in theirs.

### Passcodes

A PIN or password, with or without an EAS policy, has at least four
characters (a PIN only digits) and no run of repeated or sequential
characters longer than half of it: no `0000`, `1234` or `9876`. An EAS policy
can ask for more on top. A pattern is the dots visited, joined by index
(`0-1-2-5-8`).

After five wrong passcodes in a row, each further one locks matching out for
twice as long as the last: 30 seconds, then a minute, up to an hour. While
locked out, every try is refused without being checked. A right passcode,
or a new one, starts the count again. Under an EAS policy with a retry limit
its count runs as well, and the device is wiped when it runs out.

`/var/luna/data/.passcode` (0600) holds the lock mode and a yescrypt hash
from crypt(3), with a fresh salt for every passcode:

    {"version": 2, "pin": "$y$j7T$<salt>$<hash>"}

`/var/lib/authmanager/lockout` (0600, in a 0700 directory, written whole
under a temporary name and renamed) keeps the count, the deadline and the
biometric state, so neither a reboot nor a restart starts them again. Within
a boot the monotonic deadline holds; after a reboot, the wall-clock one,
never longer than the lockout was, and the whole lockout if the clock now
reads earlier than when it was saved. An unreadable file counts the free
tries as spent.

A file without `"version"` is luna-sysmgr's format (an unsalted SHA-1, cut
at its first NUL byte). It is still matched, and is rewritten as version 2
the first time the right passcode is given.

Tests
-----

`tests/` has unit tests on the build host (`-DBUILD_TESTING=ON`), the
sanitizer, static-analysis and warning gates; see
[tests/README.md](tests/README.md).

History
-------

Split out of [luna-sysmgr](https://github.com/webOS-ports/luna-sysmgr)
(Security.cpp, EASPolicyManager.cpp and the four surviving passcode
callbacks of SystemService.cpp). Standalone: Qt Core, glib, luna-service2,
json-c and libxcrypt are the entire dependency set - the few LunaSysMgrCommon
touchpoints (Time::curTimeMs, qFromUtf8Stl, Preferences::roundLockTimeout)
were inlined.

# Copyright and License Information

Copyright (c) 2009-2013 LG Electronics, Inc.
Copyright (c) 2026 Herman van Hazendonk <github.com@herrie.org>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this content except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
