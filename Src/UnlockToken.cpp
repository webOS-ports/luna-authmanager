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


#include "UnlockToken.h"

#include "Platform.h"

#include <string.h>

// A comparison whose time does not depend on where the strings differ.
static bool sameToken(const std::string& a, const std::string& b)
{
    if (a.size() != b.size())
        return false;

    unsigned char diff = 0;
    for (size_t i = 0; i < a.size(); ++i)
        diff |= (unsigned char) (a[i] ^ b[i]);
    return diff == 0;
}

UnlockToken::UnlockToken()
    : m_purposes(0)
    , m_expiresMs(0)
{
}

UnlockToken::~UnlockToken()
{
    clear();
}

std::string UnlockToken::issue(const std::string& owner, unsigned purposes)
{
    clear();

    if (owner.empty() || purposes == 0)
        return "";

    unsigned char raw[16];
    if (!randomBytes(raw, sizeof(raw)))
        return "";

    static const char hex[] = "0123456789abcdef";
    std::string token;
    token.reserve(2 * sizeof(raw));
    for (size_t i = 0; i < sizeof(raw); ++i) {
        token += hex[raw[i] >> 4];
        token += hex[raw[i] & 0x0f];
    }
    explicit_bzero(raw, sizeof(raw));

    m_token = token;
    m_owner = owner;
    m_purposes = purposes;
    m_expiresMs = monotonicMs() + s_lifetimeMs;
    return token;
}

bool UnlockToken::consume(const std::string& token, const std::string& owner, Purpose purpose)
{
    if (m_token.empty() || !sameToken(token, m_token))
        return false;

    // Presented: spent, whether or not it is honoured.
    const bool ok = owner == m_owner && (m_purposes & purpose) != 0 &&
                    monotonicMs() < m_expiresMs;
    clear();
    return ok;
}

void UnlockToken::clear()
{
    m_token.replace(0, m_token.size(), m_token.size(), 0);
    m_token.clear();
    m_owner.clear();
    m_purposes = 0;
    m_expiresMs = 0;
}
