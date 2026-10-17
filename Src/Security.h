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




#ifndef SECURITY_H
#define SECURITY_H

#include <stdint.h>

#include <string>

#include <luna-service2/lunaservice.h>

class EASPolicy;

class Security
{
public:

    static Security* instance();
    ~Security();

    const std::string& getLockMode() const { return m_lockMode; }

    int setPasscode(const std::string& mode, const std::string& passcode, std::string& errorText);

    // lockoutSeconds is how long the caller must wait before the next try;
    // it is set (with lockedOut) both when a try is refused for an earlier
    // lockout and when this failure starts one.
    bool matchPasscode(const std::string& passcode, int& retriesLeft, bool& lockedOut,
                       uint32_t& lockoutSeconds);

    bool passcodeSatisfiesPolicy(const EASPolicy * const policy) const;

    enum FailureCode {
        Success = 0,
        FailureEmptyPasscode = -1,
        FailureMinLength = -2,
        FailureInvalidPassword = -3,
        FailureAlphaNumeric = -4,
        FailureInvalidPin = -5,
        FailureWeakPassword = -6,
        FailureSave = -7,
        FailureWeakPasswordRepeat = -8,
        FailureWeakPasswordSequence = -9,
        FailureInvalidLockMode = -10,
        FailureBadRequest = -11
    };

    // The shortest PIN or password accepted, policy or not.
    static const uint32_t s_minPasscodeLength = 4;

    // Wrong passcodes accepted before the first lockout, the first lockout,
    // and the longest one; each lockout after the first is twice as long.
    static const uint32_t s_freeAttempts = 5;
    static const uint32_t s_firstLockoutMs = 30 * 1000;
    static const uint32_t s_maxLockoutMs = 60 * 60 * 1000;

    static bool cbDeviceWipe (LSHandle *sh, LSMessage *message, void *data);
private:

    Security();

    void registerService();

    int validatePasscode(const EASPolicy * const policy, const std::string& mode,
                          const std::string& passcode) const;

    void readLockMode();
    bool writePasscode(const std::string& mode, const std::string& hash) const;
    int attemptsLeft() const;

    void eraseDevice();

    static bool keyManagerConnected(LSHandle* handle, LSMessage* msg, void* ctxt);
    void initKeyManager();

    std::string m_lockMode;
    LSHandle* m_service;

    // Consecutive wrong passcodes, and the monotonic time until which tries
    // are refused. Reset by a right passcode or a new one.
    uint32_t m_failures;
    uint64_t m_lockedUntilMs;
};

#endif
