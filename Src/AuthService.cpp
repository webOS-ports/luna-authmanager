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
#include <string.h>
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
\param currentPasscode The passcode set now. Required whenever one is set,
       except while an EAS policy that requires a password is pending. A
       wrong one counts towards the lockout as a wrong unlock does, and the
       reply then carries errorCode -12 with lockedOut, retriesLeft and
       lockoutSeconds as matchDevicePasscode would.
*/
static bool cbSetDevicePasscode(LSHandle* lsHandle, LSMessage *message, void*)
{
    int errorCode = Security::FailureBadRequest;
    json_object* root = 0;
    json_object* prop = 0;
    std::string mode = "";
    std::string passcode = "";
    std::string current = "";
    bool haveCurrent = false;
    int retriesLeft = 0;
    bool lockedOut = false;
    uint32_t lockoutSeconds = 0;
    std::string errorText = "lockMode (a string) is required";

    const char* payload = LSMessageGetPayload(message);
    if (!payload)
        return false;

    root = json_tokener_parse(payload);
    if (!root)
        goto Done;

    // which mode are we setting?
    if (!json_object_object_get_ex(root, "lockMode", &prop) || !json_object_is_type(prop, json_type_string))
        goto Done;
    mode = json_object_get_string(prop);

    // should be a valid string if we are trying to set a pin/password
    if (json_object_object_get_ex(root, "passCode", &prop) && prop != 0) {
        if (!json_object_is_type(prop, json_type_string)) {
            errorText = "passCode must be a string";
            goto Done;
        }
        passcode = json_object_get_string(prop);
    }

    if (json_object_object_get_ex(root, "currentPasscode", &prop) && prop != 0) {
        if (!json_object_is_type(prop, json_type_string)) {
            errorText = "currentPasscode must be a string";
            goto Done;
        }
        current = json_object_get_string(prop);
        haveCurrent = true;
    }

    errorText = "";
    errorCode = Security::instance()->setPasscode(mode, passcode, haveCurrent ? &current : 0,
                                                  errorText, retriesLeft, lockedOut, lockoutSeconds);

Done:

    json_object* json = json_object_new_object();
    if (errorCode < 0) {
        json_object_object_add(json, "returnValue", json_object_new_boolean(false));
        json_object_object_add(json, "errorText", json_object_new_string(errorText.c_str()));
        json_object_object_add(json, "errorCode", json_object_new_int(errorCode));
        if (errorCode == Security::FailureCurrentPasscode) {
            json_object_object_add(json, "lockedOut", json_object_new_boolean(lockedOut));
            json_object_object_add(json, "retriesLeft", json_object_new_int(retriesLeft));
            if (lockedOut)
                json_object_object_add(json, "lockoutSeconds", json_object_new_int64(lockoutSeconds));
        }
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

    passcode.replace(0, passcode.size(), passcode.size(), 0);
    current.replace(0, current.size(), current.size(), 0);

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
    "unlockToken": string,
    "tokenLifetime": int,
    "lockedOut": boolean,
    "retriesLeft": int,
    "lockoutSeconds": int
}
\endcode

A right passcode earns an unlockToken: 32 hex digits, good once, for
tokenLifetime seconds, and only when presented on behalf of the bus name
that asked (the lock screen hands it to com.palm.display/control/setLockStatus,
Settings to a biometric enrolment). A caller with no service name gets none.

After five wrong passcodes in a row each further one locks matching out for
twice as long as the last (30 seconds first, an hour at most). While locked
out every try is refused unchecked, with lockedOut true and lockoutSeconds
saying how long is left; the failure that starts a lockout reports it too.
*/
static bool cbMatchDevicePasscode(LSHandle* lsHandle, LSMessage *message, void*)
{
    bool success = false;
    json_object* root = 0;
    json_object* key = 0;
    std::string passcode = "";
    std::string token;
    int retries = 0;
    bool lockedOut = false;
    uint32_t lockoutSeconds = 0;

    const char* payload = LSMessageGetPayload(message);
    if (!payload)
        return false;

    root = json_tokener_parse(payload);
    if (!root)
        goto Done;

    // get passcode sent by user
    if (!json_object_object_get_ex(root, "passCode", &key) || !json_object_is_type(key, json_type_string))
        goto Done; // bad arguments passed in
    passcode = json_object_get_string(key);

    success = Security::instance()->matchPasscode(passcode, retries, lockedOut, lockoutSeconds);
    passcode.replace(0, passcode.size(), passcode.size(), 0);

    if (success) {
        const char* sender = LSMessageGetSenderServiceName(message);
        token = Security::instance()->unlockToken().issue(sender ? sender : "",
            UnlockToken::PurposeUnlock | UnlockToken::PurposeEnroll);
    }

Done:

    json_object* reply = json_object_new_object();
    json_object_object_add(reply, "returnValue", json_object_new_boolean(success));
    if (success && !token.empty()) {
        json_object_object_add(reply, "unlockToken", json_object_new_string(token.c_str()));
        json_object_object_add(reply, "tokenLifetime",
                               json_object_new_int((int) (UnlockToken::s_lifetimeMs / 1000)));
    }
    if (!success) {
        json_object_object_add(reply, "lockedOut", json_object_new_boolean(lockedOut));
        json_object_object_add(reply, "retriesLeft", json_object_new_int(retries));
        if (lockedOut)
            json_object_object_add(reply, "lockoutSeconds", json_object_new_int64(lockoutSeconds));
    }

    LSError lsError;
    LSErrorInit(&lsError);

    if (!LSMessageReply(lsHandle, message, json_object_to_json_string(reply), &lsError))
        LSErrorFree(&lsError);

    if (root)
        json_object_put(root);
    json_object_put(reply);
    token.replace(0, token.size(), token.size(), 0);

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
static bool cbGetDeviceLockMode(LSHandle* lsHandle, LSMessage *message, void*)
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
        const EASPolicy* policy = EASPolicyManager::instance()->getPolicy();
        json_object_object_add(json, "lockMode", json_object_new_string(Security::instance()->getLockMode().c_str()));
        json_object_object_add(json, "policyState", json_object_new_string(EASPolicyManager::instance()->getPolicyState().c_str()));
        json_object_object_add(json, "retriesLeft", json_object_new_int(EASPolicyManager::instance()->retriesLeft()));
        // Lets a remote unlockRequiresPasscode() reproduce the old in-process
        // check exactly: pending policies that do not require a password must
        // not demand one.
        json_object_object_add(json, "policyRequiresPassword",
            json_object_new_boolean(policy != 0 && policy->passwordRequired()));
        // Whether a finger or face may unlock right now; see
        // Security::biometricAllowed(). For the lock screen to know whether
        // to arm the sensor - the say is issueBiometricToken's.
        json_object_object_add(json, "biometricAllowed",
            json_object_new_boolean(Security::instance()->biometricAllowed()));
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
static bool cbGetSecurityPolicy(LSHandle* lsHandle, LSMessage* message, void*)
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

/*
 * The methods below are on com.webos.service.auth only, and each checks who
 * calls it as well as being in a group of its own: whoever may spend or
 * mint an unlock token is named here, not only in a permission file.
 */

// The bus name of the service a biometric factor belongs to.
static const char* biometricService(const std::string& factor)
{
    if (factor == "face")
        return "com.webos.service.faceunlock";
    if (factor == "fingerprint")
        return "com.webos.service.fingerprint";
    return 0;
}

static bool callerIs(LSMessage* message, const char* name)
{
    const char* sender = LSMessageGetSenderServiceName(message);
    return name != 0 && sender != 0 && strcmp(sender, name) == 0;
}

static void replyJson(LSHandle* lsHandle, LSMessage* message, json_object* json)
{
    LSError lsError;
    LSErrorInit(&lsError);
    if (!LSMessageReply(lsHandle, message, json_object_to_json_string(json), &lsError))
        LSErrorFree(&lsError);
    json_object_put(json);
}

static void replyError(LSHandle* lsHandle, LSMessage* message, int code, const char* text)
{
    json_object* json = json_object_new_object();
    json_object_object_add(json, "returnValue", json_object_new_boolean(false));
    json_object_object_add(json, "errorCode", json_object_new_int(code));
    json_object_object_add(json, "errorText", json_object_new_string(text));
    replyJson(lsHandle, message, json);
}

// The string at key, or false if it is missing or not a string.
static bool stringParam(json_object* root, const char* key, std::string& out)
{
    json_object* prop = 0;
    if (!root || !json_object_object_get_ex(root, key, &prop) || !json_object_is_type(prop, json_type_string))
        return false;
    out = json_object_get_string(prop);
    return true;
}

/*!
\page com_webos_service_auth Service API com.webos.service.auth
\section com_webos_service_auth_consume_unlock_token consumeUnlockToken

Spend an unlock token. For com.palm.display (purpose "unlock") and for the
face and fingerprint services (purpose "enroll") only.

\code
{ "token": string, "requester": string, "purpose": "unlock" | "enroll" }
\endcode

requester is the bus name that presented the token to the caller. Replies
{"returnValue": true, "valid": boolean}; the token is spent either way.
*/
static bool cbConsumeUnlockToken(LSHandle* lsHandle, LSMessage* message, void*)
{
    const char* payload = LSMessageGetPayload(message);
    if (!payload)
        return false;

    json_object* root = json_tokener_parse(payload);
    std::string token, requester, purpose;
    if (!stringParam(root, "token", token) || !stringParam(root, "requester", requester) ||
        !stringParam(root, "purpose", purpose) || (purpose != "unlock" && purpose != "enroll")) {
        if (root)
            json_object_put(root);
        replyError(lsHandle, message, Security::FailureBadRequest,
                   "token, requester and purpose (unlock or enroll) are required");
        return true;
    }
    json_object_put(root);

    const bool allowed = purpose == "unlock"
        ? callerIs(message, "com.palm.display")
        : callerIs(message, biometricService("face")) || callerIs(message, biometricService("fingerprint"));
    if (!allowed) {
        g_warning("%s: %s may not spend a token for %s", __func__,
                  LSMessageGetSenderServiceName(message) ? LSMessageGetSenderServiceName(message) : "(anonymous)",
                  purpose.c_str());
        token.replace(0, token.size(), token.size(), 0);
        replyError(lsHandle, message, Security::FailureNotAllowed, "Not allowed");
        return true;
    }

    const bool valid = Security::instance()->unlockToken().consume(token, requester,
        purpose == "unlock" ? UnlockToken::PurposeUnlock : UnlockToken::PurposeEnroll);
    token.replace(0, token.size(), token.size(), 0);

    json_object* json = json_object_new_object();
    json_object_object_add(json, "returnValue", json_object_new_boolean(true));
    json_object_object_add(json, "valid", json_object_new_boolean(valid));
    replyJson(lsHandle, message, json);
    return true;
}

/*!
\page com_webos_service_auth
\section com_webos_service_auth_issue_biometric_token issueBiometricToken

A finger or face just matched: ask for an unlock token for requester, the
bus name that asked the biometric service to identify. Only the factor's own
service may ask ("face": com.webos.service.faceunlock, "fingerprint":
com.webos.service.fingerprint), and only while biometrics may unlock (see
getDeviceLockMode's biometricAllowed); otherwise errorCode -13 and
passcodeRequired true. The token is good for unlocking only.

\code
{ "factor": "face" | "fingerprint", "requester": string }
\endcode
*/
static bool cbIssueBiometricToken(LSHandle* lsHandle, LSMessage* message, void*)
{
    const char* payload = LSMessageGetPayload(message);
    if (!payload)
        return false;

    json_object* root = json_tokener_parse(payload);
    std::string factor, requester;
    const bool ok = stringParam(root, "factor", factor) && stringParam(root, "requester", requester) &&
                    biometricService(factor) != 0 && !requester.empty();
    if (root)
        json_object_put(root);
    if (!ok) {
        replyError(lsHandle, message, Security::FailureBadRequest,
                   "factor (face or fingerprint) and requester are required");
        return true;
    }
    if (!callerIs(message, biometricService(factor))) {
        replyError(lsHandle, message, Security::FailureNotAllowed, "Not allowed");
        return true;
    }

    std::string token;
    if (Security::instance()->biometricMatched())
        token = Security::instance()->unlockToken().issue(requester, UnlockToken::PurposeUnlock);

    json_object* json = json_object_new_object();
    if (token.empty()) {
        json_object_object_add(json, "returnValue", json_object_new_boolean(false));
        json_object_object_add(json, "errorCode", json_object_new_int(Security::FailureNotAllowed));
        json_object_object_add(json, "errorText", json_object_new_string("The passcode is required"));
        json_object_object_add(json, "passcodeRequired", json_object_new_boolean(true));
    }
    else {
        json_object_object_add(json, "returnValue", json_object_new_boolean(true));
        json_object_object_add(json, "unlockToken", json_object_new_string(token.c_str()));
        json_object_object_add(json, "tokenLifetime",
                               json_object_new_int((int) (UnlockToken::s_lifetimeMs / 1000)));
    }
    replyJson(lsHandle, message, json);
    token.replace(0, token.size(), token.size(), 0);
    return true;
}

/*!
\page com_webos_service_auth
\section com_webos_service_auth_report_biometric_failure reportBiometricFailure

A finger or face was presented and rejected (not "no face in view", not an
abort). Only the factor's own service may report it. Replies with
biometricAllowed after counting it.

\code
{ "factor": "face" | "fingerprint" }
\endcode
*/
static bool cbReportBiometricFailure(LSHandle* lsHandle, LSMessage* message, void*)
{
    const char* payload = LSMessageGetPayload(message);
    if (!payload)
        return false;

    json_object* root = json_tokener_parse(payload);
    std::string factor;
    const bool ok = stringParam(root, "factor", factor) && biometricService(factor) != 0;
    if (root)
        json_object_put(root);
    if (!ok) {
        replyError(lsHandle, message, Security::FailureBadRequest, "factor (face or fingerprint) is required");
        return true;
    }
    if (!callerIs(message, biometricService(factor))) {
        replyError(lsHandle, message, Security::FailureNotAllowed, "Not allowed");
        return true;
    }

    const bool allowed = Security::instance()->biometricFailed();

    json_object* json = json_object_new_object();
    json_object_object_add(json, "returnValue", json_object_new_boolean(true));
    json_object_object_add(json, "biometricAllowed", json_object_new_boolean(allowed));
    replyJson(lsHandle, message, json);
    return true;
}

static LSMethod s_methods[]  = {
    { "setDevicePasscode",   cbSetDevicePasscode,   LUNA_METHOD_FLAGS_NONE },
    { "matchDevicePasscode", cbMatchDevicePasscode, LUNA_METHOD_FLAGS_NONE },
    { "getDeviceLockMode",   cbGetDeviceLockMode,   LUNA_METHOD_FLAGS_NONE },
    { "getSecurityPolicy",   cbGetSecurityPolicy,   LUNA_METHOD_FLAGS_NONE },
    { 0, 0, LUNA_METHOD_FLAGS_NONE },
};

static LSMethod s_authMethods[]  = {
    { "setDevicePasscode",      cbSetDevicePasscode,      LUNA_METHOD_FLAGS_NONE },
    { "matchDevicePasscode",    cbMatchDevicePasscode,    LUNA_METHOD_FLAGS_NONE },
    { "getDeviceLockMode",      cbGetDeviceLockMode,      LUNA_METHOD_FLAGS_NONE },
    { "getSecurityPolicy",      cbGetSecurityPolicy,      LUNA_METHOD_FLAGS_NONE },
    { "consumeUnlockToken",     cbConsumeUnlockToken,     LUNA_METHOD_FLAGS_NONE },
    { "issueBiometricToken",    cbIssueBiometricToken,    LUNA_METHOD_FLAGS_NONE },
    { "reportBiometricFailure", cbReportBiometricFailure, LUNA_METHOD_FLAGS_NONE },
    { 0, 0, LUNA_METHOD_FLAGS_NONE },
};

AuthService* AuthService::s_instance = NULL;

AuthService::AuthService()
    : m_mainLoop(NULL)
    , m_legacyService(NULL)
    , m_authService(NULL)
{
}

AuthService* AuthService::instance()
{
    if (!s_instance)
        s_instance = new AuthService();

    return s_instance;
}

bool AuthService::registerName(const char* name, LSMethod* methods, LSHandle** handle)
{
    LSError lsError;
    LSErrorInit(&lsError);

    if (!LSRegister(name, handle, &lsError))
        goto Failed;

    if (!LSRegisterCategory(*handle, "/", methods, NULL, NULL, &lsError))
        goto Failed;

    if (!LSGmainAttach(*handle, m_mainLoop, &lsError))
        goto Failed;

    return true;

Failed:
    g_warning("Failed registering %s: %s", name, lsError.message);
    LSErrorFree(&lsError);

    // A name registered but not attached would hold the name with nothing
    // answering on it.
    if (*handle) {
        LSErrorInit(&lsError);
        if (!LSUnregister(*handle, &lsError))
            LSErrorFree(&lsError);
        *handle = NULL;
    }
    return false;
}

bool AuthService::init(GMainLoop* mainLoop)
{
    m_mainLoop = mainLoop;

    if (!registerName("com.palm.systemmanager", s_methods, &m_legacyService))
        return false;

    // The modern alias. Registration failure here is logged but not fatal:
    // a role file that predates the name must not take the passcode service
    // down with it.
    (void) registerName("com.webos.service.auth", s_authMethods, &m_authService);

    return true;
}

void AuthService::postDeviceLockMode()
{
    const EASPolicy* policy = EASPolicyManager::instance()->getPolicy();

    json_object* json = json_object_new_object();
    json_object_object_add(json, "returnValue", json_object_new_boolean(true));
    json_object_object_add(json, "lockMode", json_object_new_string(Security::instance()->getLockMode().c_str()));
    json_object_object_add(json, "policyState", json_object_new_string(EASPolicyManager::instance()->getPolicyState().c_str()));
    json_object_object_add(json, "retriesLeft", json_object_new_int(EASPolicyManager::instance()->retriesLeft()));
    json_object_object_add(json, "policyRequiresPassword",
        json_object_new_boolean(policy != 0 && policy->passwordRequired()));
    json_object_object_add(json, "biometricAllowed",
        json_object_new_boolean(Security::instance()->biometricAllowed()));

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
