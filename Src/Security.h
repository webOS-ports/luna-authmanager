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

#include "UnlockToken.h"

class EASPolicy;

class Security
{
public:

    static Security* instance();
    ~Security();

    const std::string& getLockMode() const { return m_lockMode; }

    // currentPasscode is the passcode being replaced, or null if the caller
    // gave none. It has to be given, and right, whenever
    // currentPasscodeRequired() says so; checking it counts towards the
    // lockout like any other try, and retriesLeft, lockedOut and
    // lockoutSeconds say how that try went (FailureCurrentPasscode).
    int setPasscode(const std::string& mode, const std::string& passcode,
                    const std::string* currentPasscode, std::string& errorText,
                    int& retriesLeft, bool& lockedOut, uint32_t& lockoutSeconds);

    // A passcode is set, so changing or removing it takes that passcode -
    // except while an EAS policy that requires a password is pending, when
    // the email app has to be able to make the owner set a compliant one.
    // Under such a policy "none" is refused anyway, so the exception can
    // replace the passcode but never remove it.
    bool currentPasscodeRequired() const;

    // lockoutSeconds is how long the caller must wait before the next try;
    // it is set (with lockedOut) both when a try is refused for an earlier
    // lockout and when this failure starts one.
    bool matchPasscode(const std::string& passcode, int& retriesLeft, bool& lockedOut,
                       uint32_t& lockoutSeconds);

    bool passcodeSatisfiesPolicy(const EASPolicy * const policy) const;

    // The token a right passcode (or an allowed biometric match) earns.
    UnlockToken& unlockToken() { return m_token; }

    /*
     * Fingerprint and face, as Android allows a convenience biometric: only
     * once the passcode has been entered since this boot, and within
     * s_biometricPasscodeMaxAgeMs of the last time it was; not while the
     * passcode is locked out; and not after s_maxBiometricFailures rejected
     * biometric tries in a row, until the passcode is entered again. The
     * biometric services report every rejection here, so the shell's own
     * counters no longer decide anything.
     */
    bool biometricAllowed() const;
    // A biometric match: true if it may unlock (and its failures restart).
    bool biometricMatched();
    // A rejected finger or face. Returns biometricAllowed() after it.
    bool biometricFailed();

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
        FailureBadRequest = -11,
        FailureCurrentPasscode = -12,
        FailureNotAllowed = -13
    };

    // The shortest PIN or password accepted, policy or not.
    static const uint32_t s_minPasscodeLength = 4;

    // Wrong passcodes accepted before the first lockout, the first lockout,
    // and the longest one; each lockout after the first is twice as long.
    static const uint32_t s_freeAttempts = 5;
    static const uint32_t s_firstLockoutMs = 30 * 1000;
    static const uint32_t s_maxLockoutMs = 60 * 60 * 1000;

    static const uint32_t s_maxBiometricFailures = 5;
    static const uint64_t s_biometricPasscodeMaxAgeMs = 72ULL * 60 * 60 * 1000;

    static bool cbDeviceWipe (LSHandle *sh, LSMessage *message, void *data);
private:

    Security();

    void registerService();

    int validatePasscode(const EASPolicy * const policy, const std::string& mode,
                          const std::string& passcode) const;

    void readLockMode();
    bool writePasscode(const std::string& mode, const std::string& hash) const;
    int attemptsLeft() const;

    // The lockout and biometric state in authStateDir()/lockout, so that
    // neither a reboot nor a restart of the daemon starts the count again.
    void loadLockoutState();
    void saveLockoutState() const;
    void passcodeProven();
    void postIfBiometricChanged(bool before) const;

    void eraseDevice();

    static bool keyManagerConnected(LSHandle* handle, LSMessage* msg, void* ctxt);
    void initKeyManager();

    std::string m_lockMode;
    LSHandle* m_service;

    // Consecutive wrong passcodes, and the monotonic time until which tries
    // are refused. Reset by a right passcode or a new one. m_lockoutMs is how
    // long the last lockout was, the most a reboot can be made to owe.
    uint32_t m_failures;
    uint64_t m_lockedUntilMs;
    uint64_t m_lockoutMs;

    // This boot's id; whether the passcode was entered during it, and the
    // wall-clock time it last was; rejected biometric tries in a row.
    std::string m_bootId;
    bool m_passcodeThisBoot;
    uint64_t m_passcodeAtWallMs;
    uint32_t m_biometricFailures;

    UnlockToken m_token;
};

#endif
