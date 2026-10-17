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




#ifndef EASPOLICYMANAGER_H
#define EASPOLICYMANAGER_H

#include <stdint.h>

#include <string>
#include <json.h>

#include <glib.h>
#include <luna-service2/lunaservice.h>

class EASPolicyManager;
class EASPolicy
{
public:
    EASPolicy(bool isDevicePolicy = false)
        : m_passwordRequired(false)
        , m_maxRetries(0)
        , m_minLength(1)
        , m_isAlphaNumeric(false)
        , m_allowSimplePassword(true)
        , m_inactivityInSeconds(9998) // highest allowable inactivity timeout
        , m_id("") 
        , m_revision (0)
        , m_isDevicePolicy(isDevicePolicy)
        , m_isDeleted(false)
    {
    }

    bool passwordRequired() const { return m_passwordRequired; }
    bool requiresAlphaNumeric() const { return m_isAlphaNumeric; }
    bool allowSimplePassword() const { return m_allowSimplePassword; }
    uint32_t maxRetries() const { return m_maxRetries; }
    uint32_t minLength() const { return m_minLength; }

    // returns a platform supported value for m_inactivityInSeconds
    uint32_t maxInactivityInSeconds() const;

    const std::string& id() const { return m_id; }
    
    json_object* toJSON() const;
    json_object* toNewJSON() const;
    bool fromNewJSON(json_object* policy);

    bool validMaxRetries() const { return m_passwordRequired && m_maxRetries > 1; }
    bool validMinLength() const { return m_passwordRequired && m_minLength > 1; }
    bool validInactivityInSeconds() const { return m_passwordRequired; }

    void merge(const EASPolicy* newPolicy);
    
private:
    bool operator== (const EASPolicy& r) const {
        return (m_passwordRequired == r.m_passwordRequired &&
                m_maxRetries == r.m_maxRetries &&
                m_minLength == r.m_minLength &&
                m_isAlphaNumeric == r.m_isAlphaNumeric &&
                m_allowSimplePassword == r.m_allowSimplePassword &&
                m_inactivityInSeconds == r.m_inactivityInSeconds);
    }

    // policy properties
    bool m_passwordRequired;
    uint32_t m_maxRetries;
    uint32_t m_minLength;
    bool m_isAlphaNumeric;
    bool m_allowSimplePassword;

    uint32_t m_inactivityInSeconds;
    
    std::string m_id;
    int64_t m_revision;
    bool m_isDevicePolicy;
    bool m_isDeleted;

    friend class EASPolicyManager;
};


class EASPolicyManager
{
public:

    static EASPolicyManager* instance();
    ~EASPolicyManager();

    bool load();

    bool policyPending() const { return (m_aggregate != 0 && !m_isEnforced); }
    const EASPolicy* getPolicy() const { return m_aggregate; }

    std::string getPolicyState() const;
    json_object* getPolicyStatus() const;

    void passwordEnforced();

    uint32_t retriesLeft() const;
    int decrementRetries();
    int resetRetries();

    
    void removeTemporaryPolicies();
    void queryDevicePolicy();
    void querySecurityPolicies();
    void setDevicePolicy (json_object* policy = NULL);
    void updateDevicePolicy (json_object* policies);
    void watchSecurityPolicies();

    static bool cbSecurityPolicy (LSHandle *sh, LSMessage *message, void *data);
    static bool cbWatchResponse (LSHandle *sh, LSMessage *message, void *data);
    static bool cbDevicePolicy (LSHandle *sh, LSMessage *message, void *data);
    static bool cbDevicePolicySaved (LSHandle *sh, LSMessage *message, void *data);
    static bool cbTempPoliciesDeleted (LSHandle *sh, LSMessage *message, void *data);

private:

    EASPolicyManager();
    EASPolicyManager(const EASPolicyManager&) = delete;
    EASPolicyManager& operator=(const EASPolicyManager&) = delete;

    void save();
    void cancelWatch();

    // Try again after db8 failed a call: it may not be up yet, or have
    // restarted under us.
    void retryLater(GSourceFunc what);
    static gboolean retryDevicePolicy(gpointer data);
    static gboolean retrySecurityPolicies(gpointer data);
    static gboolean retryWatch(gpointer data);

    void notifyPolicyChanged();

    LSHandle* m_service;

    bool m_isEnforced;
    uint32_t m_retriesLeft;

    EASPolicy* m_aggregate;
    int64_t m_lastRev;
    LSMessageToken m_callToken;

    // A device policy put/merge is waiting for its reply, and another save
    // was asked for meanwhile: it is sent when the reply comes, so a record
    // with no id yet is never put twice.
    bool m_saveInFlight;
    bool m_saveAgain;
    guint m_retrySource;
};

#endif
