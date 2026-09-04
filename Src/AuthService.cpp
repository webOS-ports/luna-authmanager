/* @@@LICENSE
*
*      Copyright (c) 2009-2013 LG Electronics, Inc.
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

#include "AuthService.h"

#include "Security.h"
#include "EASPolicyManager.h"

#include <json.h>
#include <glib.h>
#include <string>

/*
 * The four method handlers below came from luna-sysmgr's SystemService.cpp
 * with their behaviour unchanged; the other thirty-two methods that shared
 * the name there answered for subsystems (window server, WebAppMgr, modal
 * dialogs) that no longer exist and did not move with it.
 */

/*!
\page com_palm_systemmanager Service API com.palm.systemmanager
\section com_palm_systemmanager_set_device_passcode setDevicePasscode

Set (or clear) the device passcode.

\subsection syntax Syntax:
\code
{
    "lockMode": string,
    "passCode": string
}
\endcode

\param lockMode "none", "pin", "password", "pattern" or "face". \e Required.
\param passCode The secret for the chosen mode. A pattern is the nine dots
       visited, joined by index ("0-1-2-5-8"). Not required for "none".
*/
static bool cbSetDevicePasscode(LSHandle* lsHandle, LSMessage *message, void *user_data)
{
    int errorCode = 0;
    json_object* root = 0;
    json_object* prop = 0;
    std::string mode = "";
    std::string passcode = "";
    std::string errorText = "";

    const char* payload = LSMessageGetPayload(message);
    if (!payload)
        return false;

    root = json_tokener_parse(payload);
    if (!root)
        goto Done;

    // which mode are we setting?
    prop = json_object_object_get(root, "lockMode");
    if (!prop)
        goto Done;
    mode = json_object_get_string(prop);

    // should be a valid string if we are trying to set a pin/password
    prop = json_object_object_get(root, "passCode");
    if (prop)
        passcode = json_object_get_string(prop);

    errorCode = Security::instance()->setPasscode(mode, passcode, errorText);

Done:

    json_object* json = json_object_new_object();
    if (errorCode < 0) {
        json_object_object_add(json, "returnValue", json_object_new_boolean(false));
        json_object_object_add(json, "errorText", json_object_new_string(errorText.c_str()));
        json_object_object_add(json, "errorCode", json_object_new_int(errorCode));
    }
    else {
        json_object_object_add(json, "returnValue", json_object_new_boolean(true));
    }

    LSError lsError;
    LSErrorInit(&lsError);
    if (!LSMessageReply(lsHandle, message, json_object_to_json_string(json), &lsError))
        LSErrorFree(&lsError);

    json_object_put(json);
    if (root)
        json_object_put(root);

    return true;
}

/*!
\page com_palm_systemmanager
\section com_palm_systemmanager_match_device_passcode matchDevicePasscode

Check a passcode against the one set on the device.

\subsection syntax Syntax:
\code
{
    "passCode": string
}
\endcode

\subsection returns Returns:
\code
{
    "returnValue": boolean,
    "lockedOut": boolean,
    "retriesLeft": int
}
\endcode
*/
static bool cbMatchDevicePasscode(LSHandle* lsHandle, LSMessage *message, void *user_data)
{
    bool success = false;
    json_object* root = 0;
    json_object* key = 0;
    std::string passcode = "";
    int retries = 0;
    bool lockedOut = false;

    const char* payload = LSMessageGetPayload(message);
    if (!payload)
        return false;

    root = json_tokener_parse(payload);
    if (!root)
        goto Done;

    // get passcode sent by user
    key = json_object_object_get(root, "passCode");
    if (!key)
        goto Done; // bad arguments passed in
    passcode = json_object_get_string(key);

    success = Security::instance()->matchPasscode(passcode, retries, lockedOut);

Done:

    json_object* reply = json_object_new_object();
    json_object_object_add(reply, "returnValue", json_object_new_boolean(success));
    if (!success) {
        json_object_object_add(reply, "lockedOut", json_object_new_boolean(lockedOut));
        json_object_object_add(reply, "retriesLeft", json_object_new_int(retries));
    }

    LSError lsError;
    LSErrorInit(&lsError);

    if (!LSMessageReply(lsHandle, message, json_object_to_json_string(reply), &lsError))
        LSErrorFree(&lsError);

    if (root)
        json_object_put(root);
    json_object_put(reply);

    return true;
}

/*!
\page com_palm_systemmanager
\section com_palm_systemmanager_get_device_lock_mode getDeviceLockMode

Get the current lock mode, EAS policy state and retries left. Subscribable;
subscribers are notified whenever the mode or policy changes.

\subsection syntax Syntax:
\code
{
    "subscribe": boolean
}
\endcode
*/
static bool cbGetDeviceLockMode(LSHandle* lsHandle, LSMessage *message, void *user_data)
{
    bool success = true;
    bool subscribed = false;

    LSError lsError;
    LSErrorInit(&lsError);

    if (LSMessageIsSubscription(message)) {

        success = LSSubscriptionProcess(lsHandle, message, &subscribed, &lsError);
        if (!success) {
            LSErrorFree(&lsError);
        }
    }

    json_object* json = json_object_new_object();
    json_object_object_add(json, "returnValue", json_object_new_boolean(success));
    json_object_object_add(json, "subscribed", json_object_new_boolean(subscribed));
    if (success) {
        json_object_object_add(json, "lockMode", json_object_new_string(Security::instance()->getLockMode().c_str()));
        json_object_object_add(json, "policyState", json_object_new_string(EASPolicyManager::instance()->getPolicyState().c_str()));
        json_object_object_add(json, "retriesLeft", json_object_new_int(EASPolicyManager::instance()->retriesLeft()));
    }

    if (!LSMessageReply(lsHandle, message, json_object_to_json_string(json), &lsError))
        LSErrorFree(&lsError);

    json_object_put(json);

    return true;
}

/*!
\page com_palm_systemmanager
\section com_palm_systemmanager_get_security_policy getSecurityPolicy

Get the aggregate Exchange ActiveSync security policy and its status.
*/
static bool cbGetSecurityPolicy(LSHandle* lsHandle, LSMessage* message, void* user_data)
{
    bool success = false;
    json_object* json = json_object_new_object();
    EASPolicyManager* pm = EASPolicyManager::instance();
    const EASPolicy * const p = pm->getPolicy();
    json_object* policy = (p != 0 ? p->toJSON() : 0);

    if (policy) {

        json_object* status = pm->getPolicyStatus();
        if (status != 0)
            json_object_object_add(policy, "status", status);

        json_object_object_add(json, "policy", policy);

        success = true;
    }
    json_object_object_add(json, "returnValue", json_object_new_boolean(success));

    LSError lsError;
    LSErrorInit(&lsError);
    if (!LSMessageReply(lsHandle, message, json_object_to_json_string(json), &lsError))
        LSErrorFree(&lsError);

    json_object_put(json);

    return true;
}

static LSMethod s_methods[]  = {
    { "setDevicePasscode",   cbSetDevicePasscode },
    { "matchDevicePasscode", cbMatchDevicePasscode },
    { "getDeviceLockMode",   cbGetDeviceLockMode },
    { "getSecurityPolicy",   cbGetSecurityPolicy },
    { 0, 0 },
};

AuthService* AuthService::s_instance = NULL;

AuthService::AuthService()
    : m_mainLoop(NULL)
    , m_legacyService(NULL)
    , m_authService(NULL)
{
    s_instance = this;
}

AuthService* AuthService::instance()
{
    if (!s_instance)
        new AuthService();

    return s_instance;
}

bool AuthService::registerName(const char* name, LSHandle** handle)
{
    LSError lsError;
    LSErrorInit(&lsError);

    if (!LSRegister(name, handle, &lsError))
        goto Failed;

    if (!LSRegisterCategory(*handle, "/", s_methods, NULL, NULL, &lsError))
        goto Failed;

    if (!LSGmainAttach(*handle, m_mainLoop, &lsError))
        goto Failed;

    return true;

Failed:
    g_warning("Failed registering %s: %s", name, lsError.message);
    LSErrorFree(&lsError);
    return false;
}

bool AuthService::init(GMainLoop* mainLoop)
{
    m_mainLoop = mainLoop;

    if (!registerName("com.palm.systemmanager", &m_legacyService))
        return false;

    // The modern alias. Registration failure here is logged but not fatal:
    // a role file that predates the name must not take the passcode service
    // down with it.
    if (!registerName("com.webos.service.auth", &m_authService))
        m_authService = NULL;

    return true;
}

void AuthService::postDeviceLockMode()
{
    json_object* json = json_object_new_object();
    json_object_object_add(json, "returnValue", json_object_new_boolean(true));
    json_object_object_add(json, "lockMode", json_object_new_string(Security::instance()->getLockMode().c_str()));
    json_object_object_add(json, "policyState", json_object_new_string(EASPolicyManager::instance()->getPolicyState().c_str()));
    json_object_object_add(json, "retriesLeft", json_object_new_int(EASPolicyManager::instance()->retriesLeft()));

    const char* payload = json_object_to_json_string(json);

    LSHandle* handles[2] = { m_legacyService, m_authService };
    for (int i = 0; i < 2; ++i) {
        if (!handles[i])
            continue;
        LSError lsError;
        LSErrorInit(&lsError);
        if (!LSSubscriptionPost(handles[i], "/", "getDeviceLockMode", payload, &lsError))
            LSErrorFree(&lsError);
    }

    json_object_put(json);
}
