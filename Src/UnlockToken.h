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


#ifndef UNLOCK_TOKEN_H
#define UNLOCK_TOKEN_H

#include <stdint.h>

#include <string>

/**
 * The proof that someone just showed the device passcode (or, within the
 * biometric rules, a finger or a face), handed to whoever showed it and
 * spent by the service it is shown to.
 *
 * A token is 128 random bits, written as 32 hex digits. It is bound to the
 * bus name it was issued to, lives s_lifetimeMs, and is good once: the
 * first time it is presented, right owner and purpose or not, it is gone.
 * Only one is outstanding at a time; issuing another replaces it.
 *
 * luna-displaymanager spends one to unlock the screen (PurposeUnlock); the
 * biometric services spend one to enrol a finger or a face (PurposeEnroll),
 * so a token won by a biometric match is issued for unlocking only.
 */
class UnlockToken
{
public:
    enum Purpose {
        PurposeUnlock = 1 << 0,
        PurposeEnroll = 1 << 1
    };

    static const uint64_t s_lifetimeMs = 30 * 1000;

    UnlockToken();
    ~UnlockToken();

    // A new token for owner, good for purposes (a mask of Purpose), in place
    // of any earlier one. Empty if owner is empty or no random bytes came.
    std::string issue(const std::string& owner, unsigned purposes);

    // True once for the token issue() returned, if presented on behalf of
    // owner, for one of its purposes, before it expired.
    bool consume(const std::string& token, const std::string& owner, Purpose purpose);

    // Forget the outstanding token, e.g. when the passcode changes.
    void clear();

private:
    std::string m_token;
    std::string m_owner;
    unsigned m_purposes;
    uint64_t m_expiresMs;
};

#endif // UNLOCK_TOKEN_H
