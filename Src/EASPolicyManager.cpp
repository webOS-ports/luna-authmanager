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




#include "EASPolicyManager.h"

#include "Security.h"
#include "AuthService.h"

#include <glib.h>
#include <math.h>
#include <stdlib.h>

/*

Version 1
 
{
     password: {
        enabled: <bool>,         // is a password required?
        minLength: <int>,        // < 2 implies no minLength
        maxRetries: <int>,        // 0 implies unlimited retries / no lockout
        alphaNumeric: <bool>    // true = requires password, false = allow pin
    },
    inactivityInSeconds: <int>, // > 9998 means set to 0
    id: <string>,
    status: {
        enforced: <bool>,        // policy has been enforced completely
        retriesLeft: <int>        // only meaningful if maxRetries > 0
    }
}

Version 2

{
    version: <int>,

    status: {
        enforced: <bool>,
        retriesLeft: <int>
    },

    policies: [
        {
            password: {
                enabled: <bool>,
                minLength: <int>,
                maxRetries: <int>,
                alphaNumeric: <bool>
            },
            inactivityInSeconds: <int>,
            id: <string>
        },
        ...
    ]
}

Version 3 - mojodb file.
Device Policy fields defined in: https://wiki.palm.com/display/Nova/Device+Policy+Fields

*/

static EASPolicyManager* s_instance = 0;

// Seconds before a failed db8 call is made again.
static const guint s_retrySeconds = 5;

// A count or length from a policy record: anything below 0 is 0 and anything
// past 32 bits is the largest, rather than -1 turning into 4294967295.
static uint32_t policyCount(json_object* key, uint32_t missing)
{
    if (!key)
        return missing;
    int64_t v = json_object_get_int64(key);
    if (v < 0)
        return 0;
    if (v > (int64_t) UINT32_MAX)
        return UINT32_MAX;
    return (uint32_t) v;
}

// The db8 reply's "results", if the call succeeded and it is an array.
static json_object* resultsOf(json_object* root, const char* func)
{
    json_object* rv = 0;
    if (!json_object_object_get_ex(root, "returnValue", &rv) || !json_object_get_boolean(rv)) {
        g_warning("%s: db8 call failed: %s", func, json_object_to_json_string(root));
        return 0;
    }

    json_object* results = 0;
    if (!json_object_object_get_ex(root, "results", &results)
            || !json_object_is_type(results, json_type_array)) {
        g_warning("%s: no results array in the reply", func);
        return 0;
    }
    return results;
}


EASPolicyManager* EASPolicyManager::instance()
{
    if (G_UNLIKELY(s_instance == 0))
        s_instance = new EASPolicyManager;
    return s_instance;
}

EASPolicyManager::EASPolicyManager()
    : m_service(0)
    , m_isEnforced(false)
    , m_retriesLeft(0)
    , m_aggregate(0)
    , m_lastRev(0)
    , m_callToken(0)
    , m_saveInFlight(false)
    , m_saveAgain(false)
    , m_retrySource(0)
{
}

EASPolicyManager::~EASPolicyManager()
{
    if (m_retrySource)
        g_source_remove(m_retrySource);
    delete m_aggregate;
    m_aggregate = NULL;
    s_instance = NULL;
}


void EASPolicyManager::removeTemporaryPolicies()
{
    if (!m_service) {
        g_warning ("Service handle not available yet, cannot query device policy");
        return;
    }

    LSError lserror;
    LSErrorInit (&lserror);

    gchar* query = g_strdup ("{\"query\":{\"from\":\"com.palm.securitypolicy:1\", \"where\":[{\"prop\":\"isTemp\",\"op\":\"=\",\"val\":true}]}}");
    g_debug ("%s: Calling %s with %s", __func__, "palm://com.palm.db/del", query);
    bool result = LSCallOneReply (m_service, "palm://com.palm.db/del", query, &EASPolicyManager::cbTempPoliciesDeleted, this, NULL, &lserror);
    if (!result) {
        g_warning ("%s: Failed at %s with message %s", __func__, lserror.func, lserror.message);
        LSErrorFree (&lserror);
    }
    g_free (query);
}

bool EASPolicyManager::cbTempPoliciesDeleted (LSHandle*, LSMessage *message, void*)
{
    const char* str = LSMessageGetPayload(message);
    json_object *root = 0, *returnValue = 0, *obj = 0;
    bool success = false;
    int count = 0;

    if (!str)
        goto done;

    g_debug ("%s: response %s", __func__, str);

    root = json_tokener_parse(str);
    if (!root)
        goto done;
    
    returnValue = json_object_object_get (root, "returnValue");
    if (!returnValue) {
        g_warning ("%s: check for returnValue failed", __func__);
        goto done;
    }

    success = json_object_get_boolean (returnValue);
    if (!success) {
        g_warning ("%s: delete of temporary policies failed", __func__);
        goto done;
    }

    obj = json_object_object_get (root, "count");
    if (!obj) {
        g_warning ("%s: count missing", __func__);
        goto done;
    }

    count = json_object_get_int (obj);
    g_message ("%s: Deleted %d temporary policies", __func__, count);

done:
    if (root)
        json_object_put (root);
    // temporary policies cleared, query device policy now
    EASPolicyManager::instance()->queryDevicePolicy();
    return true;
}

void EASPolicyManager::queryDevicePolicy()
{
    if (!m_service) {
        g_warning ("Service handle not available yet, cannot query device policy");
        return;
    }

    LSError lserror;
    LSErrorInit (&lserror);

    gchar* query = g_strdup ("{\"query\":{\"from\":\"com.palm.securitypolicy.device:1\"}}");
    bool result = LSCallOneReply (m_service, "palm://com.palm.db/find", query, &EASPolicyManager::cbDevicePolicy, this, NULL, &lserror);
    if (!result) {
        g_warning ("%s: Failed at %s with message %s", __func__, lserror.func, lserror.message);
        LSErrorFree (&lserror);
    }
    g_free (query);
}

bool EASPolicyManager::cbDevicePolicy (LSHandle*, LSMessage *message, void*)
{
    EASPolicyManager* pm = EASPolicyManager::instance();
    const char* str = LSMessageGetPayload(message);
    json_object *root = 0, *results = 0, *policy = 0;

    if (str)
        root = json_tokener_parse(str);
    if (root)
        results = resultsOf(root, __func__);

    // An error is not "no device policy": writing a default one here would
    // add a second record next to the real one, and reset its retry count.
    if (!results) {
        if (root)
            json_object_put (root);
        pm->retryLater(&EASPolicyManager::retryDevicePolicy);
        return true;
    }

    if (json_object_array_length (results) == 0) {
        g_debug ("No security policies set, setting a default policy");
        pm->setDevicePolicy();
        goto done;
    }

    if (json_object_array_length (results) > 1) {
        g_warning ("Device policy > 1, BUG! Using the 1st");
    }

    policy  = json_object_array_get_idx (results, 0);
    if (!policy) {
        g_warning ("No device policy at index 0, BUG!");
        goto done;
    }

    pm->setDevicePolicy (policy);

done:
    pm->querySecurityPolicies();

    json_object_put (root);

    return true;
}

void EASPolicyManager::setDevicePolicy (json_object* policy)
{
    if (m_aggregate)
        delete m_aggregate;

    // resetting the aggregate before parsing the security policies again.
    // no special handling required for changes or policy decisions
    m_lastRev = 0;
    m_aggregate = new EASPolicy(true);

    if (policy) {
        m_aggregate->fromNewJSON (policy);

        json_object* prop = json_object_object_get(policy, "status");
        if (prop) {

            json_object* key = json_object_object_get(prop, "enforced");
            m_isEnforced = (key == 0 ? false : json_object_get_boolean(key));


            key = json_object_object_get(prop, "retriesLeft");
            m_retriesLeft = policyCount(key, m_aggregate->maxRetries());
        }
        else {
            m_isEnforced = false;
            m_retriesLeft = m_aggregate->maxRetries();
        }

    }
    else {
        // if no device policy is available, save the default policy
        notifyPolicyChanged();
    }

}

void EASPolicyManager::querySecurityPolicies()
{
    if (!m_service) {
        g_warning ("Service handle not available yet, cannot query device policy");
        return;
    }

    LSError lserror;
    LSErrorInit (&lserror);

    gchar* query = g_strdup ("{\"query\":{\"from\":\"com.palm.securitypolicy:1\", \"incDel\" : true}}");
    bool result = LSCallOneReply (m_service, "palm://com.palm.db/find", query, &EASPolicyManager::cbSecurityPolicy, this, NULL, &lserror);
    if (!result) {
        g_warning ("%s: Failed at %s with message %s", __func__, lserror.func, lserror.message);
        LSErrorFree (&lserror);
    }
    g_free (query);
}


bool EASPolicyManager::cbSecurityPolicy (LSHandle*, LSMessage *message, void*)
{
    EASPolicyManager* pm = EASPolicyManager::instance();
    const char* str = LSMessageGetPayload(message);
    json_object *root = 0, *results = 0;

    if (str)
        root = json_tokener_parse(str);
    if (root)
        results = resultsOf(root, __func__);

    // Without the policies there is no watch either: ask again.
    if (results)
        pm->updateDevicePolicy (results);
    else
        pm->retryLater(&EASPolicyManager::retrySecurityPolicies);

    if (root)
        json_object_put (root);

    return true;
}


void EASPolicyManager::updateDevicePolicy (json_object* policies)
{
    EASPolicy* oldPolicy = m_aggregate;

    // resetting the aggregate before parsing the security policies again.
    // no special handling required for changes or policy decisions
    m_lastRev = 0;
    m_aggregate = new EASPolicy(true);
    if (oldPolicy) // inherit the id from the old policy
        m_aggregate->m_id = oldPolicy->m_id;

    for (size_t index = 0; index < json_object_array_length (policies); ++index) {
        json_object* policy = json_object_array_get_idx(policies, index);
        if (!policy) {
            g_warning ("Index %zu has no security policy", index);
            continue;
        }
        g_debug ("Importing policy %s", json_object_get_string(policy));

        EASPolicy newPolicy;
        newPolicy.fromNewJSON (policy);
        if (!newPolicy.m_isDevicePolicy && !newPolicy.m_isDeleted)
            m_aggregate->merge (&newPolicy);

        if (newPolicy.m_revision > m_lastRev) {
            m_lastRev = newPolicy.m_revision;
        }
    }

    if (oldPolicy) {
        if (oldPolicy->maxRetries() != m_aggregate->maxRetries()) {
            g_debug("New policy has different number of retries: old (%u), new (%u)",
                    oldPolicy->maxRetries(), m_aggregate->maxRetries());
            m_retriesLeft = m_aggregate->maxRetries();
        }
        else {
            g_debug("Not updating retriesLeft");
        }
    }
    else
        m_retriesLeft = m_aggregate->maxRetries();

    if (oldPolicy && *oldPolicy == *m_aggregate) {
        watchSecurityPolicies(); // policy not changed, reset watch here
        delete oldPolicy;
    }
    else {
        notifyPolicyChanged();
        if (oldPolicy)
            delete oldPolicy;
        // watch will be set after saving the new policy
    }
}


void EASPolicyManager::cancelWatch()
{
    if (!m_callToken)
        return;

    LSError lserror;
    LSErrorInit (&lserror);

    g_debug ("Cancelling call token %lu", m_callToken);
    if (!LSCallCancel (m_service, m_callToken, &lserror)) {
        g_warning ("Unable to cancel call with token %lu error message %s", m_callToken, lserror.message);
        LSErrorFree (&lserror);
    }
    m_callToken = 0;
}

void EASPolicyManager::watchSecurityPolicies()
{
    LSError lserror;
    LSErrorInit (&lserror);

    if (!m_service) {
        g_warning ("%s: no service handle; not watching", __func__);
        return;
    }

    cancelWatch();

    gchar* query = g_strdup_printf ("{\"query\":{\"from\":\"com.palm.securitypolicy:1\",\"where\":[{\"prop\":\"_rev\",\"op\":\">\",\"val\":%lld}], \"incDel\": true }}", (long long) m_lastRev);
    g_message ("Setting watch with paramters %s", query);
    bool result = LSCall (m_service, "palm://com.palm.db/watch", query, &EASPolicyManager::cbWatchResponse, this,&m_callToken, &lserror);
    if (!result) {
        g_warning ("%s: Failed at %s with message %s", __func__, lserror.func, lserror.message);
        LSErrorFree (&lserror);
        m_callToken = 0;
        retryLater(&EASPolicyManager::retryWatch);
    }
    g_free (query);
}


bool EASPolicyManager::cbWatchResponse (LSHandle*, LSMessage *message, void*)
{
    EASPolicyManager* pm = EASPolicyManager::instance();
    const char* str = LSMessageGetPayload(message);
    json_object *root = 0, *label = 0;
    bool fired = false;

    if (!str)
        goto error;
    g_debug ("%s: response %s", __func__, str);

    root = json_tokener_parse(str);
    if (!root)
        goto error;

    label = json_object_object_get (root, "returnValue");
    if (!label)
        goto error;

    if (!json_object_get_boolean (label)) {
        // db8 dropped the watch (it restarted, say): set it up again.
        g_warning ("%s: returnValue is false", __func__);
        pm->cancelWatch();
        pm->retryLater(&EASPolicyManager::retryWatch);
        goto error;
    }

    // The first reply only says the watch is set.
    label = json_object_object_get (root, "fired");
    if (!label) {
        goto error;
    }

    fired = json_object_get_boolean (label);
    if (!fired) {
        g_warning ("%s: fired is false", __func__);
        goto error;
    }

    // A watch fires once; the call stays open in ls2 until cancelled.
    pm->cancelWatch();

    g_debug ("%s: Watch on security policy fired, query security policy", __func__);
    pm->querySecurityPolicies();

error:

    if (root)
        json_object_put (root);

    return true;
}


bool EASPolicyManager::load()
{
    m_service = AuthService::instance()->serviceHandle();

    if (!m_service) {
        g_warning ("system service handle is missing");
        return false;
    }

    if (!m_aggregate)
        m_aggregate = new EASPolicy (true);

    if (!m_aggregate)
        return false;

#if !defined(TARGET_DESKTOP) 
    removeTemporaryPolicies();
    // clean up temporary policies before restoring current policies

#else
    setDevicePolicy();
#endif

    return true;
}


void EASPolicyManager::save()
{
    if (!m_service) {
        g_warning ("Service handle not available yet, cannot query device policy");
        return;
    }

    if (m_saveInFlight) {
        m_saveAgain = true;
        return;
    }

    LSError lserror;
    LSErrorInit (&lserror);

    cancelWatch();

    json_object* policyJson = m_aggregate->toNewJSON();
    json_object_object_add(policyJson, "status", getPolicyStatus());
    gchar* policyStr = g_strdup_printf ("{ \"objects\":[%s]}", json_object_to_json_string (policyJson));
    g_message ("%s: Writing device policy %s to mojodb", __func__, policyStr);

    const char* uri = m_aggregate->m_id.empty() ? "palm://com.palm.db/put" : "palm://com.palm.db/merge";
    m_saveInFlight = LSCallOneReply (m_service, uri, policyStr,
                                     &EASPolicyManager::cbDevicePolicySaved, this, NULL, &lserror);
    if (!m_saveInFlight) {
        g_warning ("%s: Failed at %s with message %s", __func__, lserror.func, lserror.message);
        LSErrorFree (&lserror);
    }

    json_object_put (policyJson);
    g_free (policyStr);

    // No reply will come to set the watch again.
    if (!m_saveInFlight)
        watchSecurityPolicies();
}

bool EASPolicyManager::cbDevicePolicySaved (LSHandle*, LSMessage *message, void*)
{
    const char* str = LSMessageGetPayload(message);
    json_object *root = 0, *label = 0, *policy = 0, *results = 0;
    bool returnValue = false;
    std::string id;

    if (!str)
        goto error;

    g_debug ("%s: response %s", __func__, str);

    root = json_tokener_parse(str);
    if (!root)
        goto error;

    label = json_object_object_get (root, "returnValue");
    if (!label)  {
        g_warning ("No returnValue available");
        goto error;
    }

    returnValue = json_object_get_boolean (label);
    if (!returnValue) {
        g_warning ("returnValue is false, call failed");
        goto error;
    }

    results = json_object_object_get (root, "results");
    if (!results || !json_object_is_type (results, json_type_array)) {
        g_warning ("No results array in device policy, call to store device policy failed");
        goto error;
    }

    if (json_object_array_length (results) != 1) {
        g_warning ("Device policy != 1, BUG! Using the 1st");
    }

    policy = json_object_array_get_idx(results, 0);
    if (!policy) {
        g_warning ("No policy in list, cannot update id");
        goto error;
    }

    label = json_object_object_get (policy, "id");
    if (!label)  {
        g_warning ("No id available");
        goto error;
    }

    id = json_object_get_string (label);
    if (id.empty()) {
        g_warning ("Invalid id");
        goto error;
    }

    // The rev is deliberately not read here - the watch rev must not move
    // past updates that landed between the last policy query and this save
    // (see below). It used to be validated anyway, and a reply with a good
    // id but no rev would discard the id, leaving m_id empty so the *next*
    // save took the put branch and duplicated the device-policy record.

    // Every live path replaces m_aggregate synchronously before a save reply
    // can arrive; the one state where it is NULL here is a reply in flight
    // across destruction, where instance() just resurrected an empty manager.
    // instance() - not the ctx argument - is deliberate: in that same state
    // ctx would be a dangling pointer to the destroyed manager. m_service is
    // NULL there too, so the error path's re-watch would only move the crash
    // into LSCall - return outright instead.
    {
        EASPolicyManager* pm = EASPolicyManager::instance();
        if (!pm->m_aggregate) {
            g_warning ("%s: no aggregate policy to update", __func__);
            if (root)
                json_object_put (root);
            return true;
        }

        if (pm->m_aggregate->m_id != id) {
            pm->m_aggregate->m_id = id;
            g_debug ("%s: updated id to %s", __func__, id.c_str());
        }
    }

    // do not update the watch rev after saving the device policy
    // otherwise the watch will miss upates that might have
    // occured between the last query of the security policies
    // and the saving of this device policy.
    // Note, this will cause the watch to always get triggered
    // once after saving a device policy, due to the updated 
    // revision of the device policy

error:
    if (root)
        json_object_put (root);

    {
        EASPolicyManager* pm = EASPolicyManager::instance();
        pm->m_saveInFlight = false;
        if (pm->m_saveAgain) {
            // save() sets the watch once the last save is answered.
            pm->m_saveAgain = false;
            pm->save();
        }
        else {
            pm->watchSecurityPolicies();
        }
    }
    return true;
}

void EASPolicyManager::retryLater(GSourceFunc what)
{
    if (m_retrySource)
        g_source_remove(m_retrySource);
    m_retrySource = g_timeout_add_seconds(s_retrySeconds, what, this);
}

gboolean EASPolicyManager::retryDevicePolicy(gpointer)
{
    EASPolicyManager* pm = EASPolicyManager::instance();
    pm->m_retrySource = 0;
    pm->queryDevicePolicy();
    return G_SOURCE_REMOVE;
}

gboolean EASPolicyManager::retrySecurityPolicies(gpointer)
{
    EASPolicyManager* pm = EASPolicyManager::instance();
    pm->m_retrySource = 0;
    pm->querySecurityPolicies();
    return G_SOURCE_REMOVE;
}

gboolean EASPolicyManager::retryWatch(gpointer)
{
    EASPolicyManager* pm = EASPolicyManager::instance();
    pm->m_retrySource = 0;
    pm->watchSecurityPolicies();
    return G_SOURCE_REMOVE;
}


void EASPolicyManager::notifyPolicyChanged()
{
    // immediately enforce policy?
    m_isEnforced = Security::instance()->passcodeSatisfiesPolicy(m_aggregate);

    g_message("policy enforcement succeeded? %d", m_isEnforced);

    AuthService::instance()->postDeviceLockMode();

#if !defined(TARGET_DESKTOP)
    save();
#endif
}


std::string EASPolicyManager::getPolicyState() const
{
    if (m_aggregate == 0)
        return "none";
    return m_isEnforced ? "active" : "pending";
}

json_object* EASPolicyManager::getPolicyStatus() const
{
    if (m_aggregate == 0)
        return 0;

    json_object* status = json_object_new_object();
    json_object_object_add(status, "enforced", json_object_new_boolean(m_isEnforced));
    json_object_object_add(status, "retriesLeft", json_object_new_int(m_retriesLeft));

    return status;
}

void EASPolicyManager::passwordEnforced()
{
    if (!policyPending())
        return;

    m_isEnforced = true;
    m_retriesLeft = m_aggregate->maxRetries();

    save();
}

uint32_t EASPolicyManager::retriesLeft() const
{
    if (m_aggregate == 0 || !m_aggregate->validMaxRetries() || !m_isEnforced)
        return 0;
    return m_retriesLeft;
}

int EASPolicyManager::decrementRetries()
{
    if (m_aggregate == 0 || !m_aggregate->validMaxRetries() || !m_isEnforced)
        return 0;

    if (m_retriesLeft > 0) {
        m_retriesLeft--;
    }

    save();
    return m_retriesLeft;
}

int EASPolicyManager::resetRetries()
{
    if (m_aggregate == 0 || !m_aggregate->validMaxRetries() || !m_isEnforced )
        return 0;
    
    m_retriesLeft = m_aggregate->maxRetries();

    save();
    return m_retriesLeft;
}

/*********************************************************************************************/

json_object* EASPolicy::toNewJSON() const
{
    json_object* policy = json_object_new_object();

    json_object_object_add(policy, "devicePasswordEnabled", json_object_new_boolean(m_passwordRequired));
    json_object_object_add(policy, "minDevicePasswordLength", json_object_new_int(m_minLength));
    json_object_object_add(policy, "maxDevicePasswordFailedAttempts", json_object_new_int(m_maxRetries));
    json_object_object_add(policy, "alphanumericDevicePasswordRequired", json_object_new_boolean(m_isAlphaNumeric));
    json_object_object_add(policy, "allowSimpleDevicePassword", json_object_new_boolean(m_allowSimplePassword));

    json_object_object_add(policy, "maxInactivityTimeDeviceLock", json_object_new_int(m_inactivityInSeconds));

    if (!m_id.empty()) {
        json_object_object_add(policy, "_id", json_object_new_string(m_id.c_str()));
    }
    if (m_isDevicePolicy)
        json_object_object_add(policy, "_kind", json_object_new_string("com.palm.securitypolicy.device:1"));

    return policy;
}

json_object* EASPolicy::toJSON() const
{
    json_object* policy = json_object_new_object();

    json_object* password = json_object_new_object();
    json_object_object_add(password, "enabled", json_object_new_boolean(m_passwordRequired));
    json_object_object_add(password, "minLength", json_object_new_int(m_minLength));
    json_object_object_add(password, "maxRetries", json_object_new_int(m_maxRetries));
    json_object_object_add(password, "alphaNumeric", json_object_new_boolean(m_isAlphaNumeric));
    if (m_passwordRequired && !m_isAlphaNumeric) {
        json_object_object_add(password, "allowSimplePassword", json_object_new_boolean(m_allowSimplePassword));
    }

    json_object_object_add (policy, "password", password);

    json_object_object_add(policy, "inactivityInSeconds", json_object_new_int(m_inactivityInSeconds));

    json_object_object_add(policy, "id", json_object_new_string(m_id.c_str()));

    return policy;
}

bool EASPolicy::fromNewJSON(json_object* policy)
{
    json_object *key = 0;

    key = json_object_object_get(policy, "devicePasswordEnabled");
    if (key)
        m_passwordRequired = json_object_get_boolean(key);
    else
        m_passwordRequired = false;

    key = json_object_object_get(policy, "alphanumericDevicePasswordRequired");
    if (key)
        m_isAlphaNumeric = json_object_get_boolean(key);
    else 
        m_isAlphaNumeric = false;

    m_minLength = policyCount(json_object_object_get(policy, "minDevicePasswordLength"), 1);
    m_maxRetries = policyCount(json_object_object_get(policy, "maxDevicePasswordFailedAttempts"), 1);
    m_inactivityInSeconds = policyCount(json_object_object_get(policy, "maxInactivityTimeDeviceLock"), 0);

    key = json_object_object_get(policy, "allowSimpleDevicePassword");
    if (key)
        m_allowSimplePassword = json_object_get_boolean(key);
    else
        m_allowSimplePassword = true;

    key = json_object_object_get(policy, "_id");
    if (key) {
        const char* str = json_object_get_string(key);
        m_id = (str != NULL ? str : "");
    }

    key = json_object_object_get (policy, "_rev");
    m_revision = key ? json_object_get_int64 (key) : 0;
    
    key = json_object_object_get(policy, "_kind");
    if (key) {
        std::string kind = json_object_get_string(key);
        if (kind == "com.palm.securitypolicy.device:1")
            m_isDevicePolicy = true;
        else 
            m_isDevicePolicy = false;
    }
    else {
        m_isDevicePolicy = false;
    }

    key = json_object_object_get(policy, "_del");
    if (key) {
        m_isDeleted = json_object_get_boolean(key);
    }
    else {
        m_isDeleted = false;
    }

    return !m_id.empty();
}

uint32_t EASPolicy::maxInactivityInSeconds() const
{
    if (m_inactivityInSeconds < 60) {

        // round to the lowest 30 second interval
        return m_inactivityInSeconds - (m_inactivityInSeconds % 30);
    }
    else if (m_inactivityInSeconds < 9999) {

        // round to the lowest 60 second interval
        return m_inactivityInSeconds - (m_inactivityInSeconds % 60);
    }
    return 0; // default to the strictest timeout
}

void EASPolicy::merge(const EASPolicy* newPolicy)
{
    // update password
    if (!this->m_passwordRequired && newPolicy->m_passwordRequired) {

        // first time we are trying to enforce a password
        this->m_passwordRequired = newPolicy->m_passwordRequired;
        this->m_maxRetries = newPolicy->m_maxRetries;
        this->m_minLength = newPolicy->m_minLength;
        this->m_isAlphaNumeric = newPolicy->m_isAlphaNumeric;
        this->m_allowSimplePassword = newPolicy->m_allowSimplePassword;

        // inactivity should be ignored if no password is required
        this->m_inactivityInSeconds = newPolicy->maxInactivityInSeconds();
    }
    else if (this->m_passwordRequired && newPolicy->m_passwordRequired) {

        // update inactivity timeout
        if (newPolicy->m_inactivityInSeconds < this->m_inactivityInSeconds) {
            this->m_inactivityInSeconds = newPolicy->maxInactivityInSeconds();
        }

        // possibly update the terms of password enforcement
        if (newPolicy->validMaxRetries()) {
            if (!this->validMaxRetries() || newPolicy->m_maxRetries < this->m_maxRetries) {
                this->m_maxRetries = newPolicy->m_maxRetries;
            }
        }

        // alphanumeric is stricter than allowing a PIN
        if (!this->m_isAlphaNumeric && newPolicy->m_isAlphaNumeric) {
            this->m_isAlphaNumeric = newPolicy->m_isAlphaNumeric;
        }

        // not allowing simple device password is stricter
        if (this->m_allowSimplePassword && !newPolicy->m_allowSimplePassword) {
            this->m_allowSimplePassword = newPolicy->m_allowSimplePassword;
        }

        // chose the highest min length
        if (newPolicy->validMinLength() && newPolicy->m_minLength > this->m_minLength) {
            this->m_minLength = newPolicy->m_minLength;
        }
    }

}

