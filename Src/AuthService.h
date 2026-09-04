/* @@@LICENSE
*
*      Copyright (c) 2026 Herman van Hazendonk <github.com@herrie.org>
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
* http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*
* LICENSE@@@ */

#ifndef AUTH_SERVICE_H
#define AUTH_SERVICE_H

#include <glib.h>
#include <luna-service2/lunaservice.h>

/**
 * The bus face of the authentication daemon.
 *
 * Registers two names serving the same four methods:
 *
 *  - com.palm.systemmanager: the name every existing caller knows -
 *    cardshell's lock screens, the Settings screen-lock page, the phone
 *    PIN cards and the Enyo 1 authlib. It survives the split from
 *    luna-sysmgr precisely so none of them need a flag day.
 *
 *  - com.webos.service.auth: the name new work should call. Today it is an
 *    exact alias; the plan is for biometric orchestration (fingerprint,
 *    face) to land here, folded into the same retry and lockout budget the
 *    passcode already uses.
 *
 * Methods: setDevicePasscode, matchDevicePasscode, getDeviceLockMode
 * (subscribable), getSecurityPolicy.
 */
class AuthService
{
public:
    static AuthService* instance();

    bool init(GMainLoop* mainLoop);

    // The com.palm.systemmanager handle. EASPolicyManager issues its db8
    // calls through it, as it did when SystemService owned the name.
    LSHandle* serviceHandle() const { return m_legacyService; }
    GMainLoop* mainLoop() const { return m_mainLoop; }

    // Push the current lock mode / policy state / retries to every
    // getDeviceLockMode subscriber, on both names.
    void postDeviceLockMode();

private:
    AuthService();

    bool registerName(const char* name, LSHandle** handle);

    static AuthService* s_instance;

    GMainLoop* m_mainLoop;
    LSHandle* m_legacyService;   // com.palm.systemmanager
    LSHandle* m_authService;     // com.webos.service.auth
};

#endif // AUTH_SERVICE_H
