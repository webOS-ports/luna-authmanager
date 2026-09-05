luna-authmanager
================

Summary
-------
The LuneOS authentication manager: device lock modes, EAS policy, retry and lockout state

The LuneOS authentication manager: device lock modes (PIN, password,
pattern, and "face" for a future adapter), Exchange ActiveSync policy
enforcement, retry/lockout state, keymanager password sync, and device
wipe on retry exhaustion.

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

* `setDevicePasscode` — `{"lockMode": "none"|"pin"|"password"|"pattern"|"face", "passCode": string}`
* `matchDevicePasscode` — `{"passCode": string}` → `{returnValue, lockedOut, retriesLeft}`
* `getDeviceLockMode` — subscribable → `{lockMode, policyState, retriesLeft}`
* `getSecurityPolicy` — aggregate EAS policy and status

History
-------

Split out of [luna-sysmgr](https://github.com/webOS-ports/luna-sysmgr)
(Security.cpp, EASPolicyManager.cpp and the four surviving passcode
callbacks of SystemService.cpp). Standalone: Qt Core, glib, luna-service2
and json-c are the entire dependency set - the few LunaSysMgrCommon
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
