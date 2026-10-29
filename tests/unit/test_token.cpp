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

// The unlock token a right passcode earns: random, bound to the name that
// asked, good once, for 30 seconds, and spent only by com.palm.display (to
// unlock) or by the biometric services (to enrol).

#include "fixture.h"

#include <set>

namespace {

const char* const kShell = "com.webos.surfacemanager-cardshell";
const char* const kDisplay = "com.palm.display";
const char* const kFace = "com.webos.service.faceunlock";
const char* const kFinger = "com.webos.service.fingerprint";

bool isHex32(const std::string& s)
{
    if (s.size() != 32)
        return false;
    for (char c : s)
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')))
            return false;
    return true;
}

} // namespace

TEST_F(AuthTest, ARightPasscodeEarnsAToken)
{
    start();
    boot();
    ASSERT_TRUE(setPasscode("pin", "7351").returnValue);

    Reply wrong = matchPasscode("0482", kShell);
    EXPECT_TRUE(wrong.unlockToken.empty());

    Reply right = matchPasscode("7351", kShell);
    ASSERT_TRUE(right.returnValue);
    EXPECT_TRUE(isHex32(right.unlockToken)) << right.unlockToken;
    EXPECT_NE(right.raw.find("\"tokenLifetime\": 30"), std::string::npos) << right.raw;
}

TEST_F(AuthTest, TokensAreNotRepeated)
{
    start();
    boot();
    ASSERT_TRUE(setPasscode("pin", "7351").returnValue);
    std::set<std::string> seen;
    for (int i = 0; i < 50; ++i)
        seen.insert(matchPasscode("7351", kShell).unlockToken);
    EXPECT_EQ(seen.size(), 50u);
}

TEST_F(AuthTest, ATokenUnlocksOnce)
{
    start();
    boot();
    ASSERT_TRUE(setPasscode("pin", "7351").returnValue);
    std::string t = matchPasscode("7351", kShell).unlockToken;

    Reply first = consumeToken(kDisplay, t, kShell);
    EXPECT_TRUE(first.returnValue);
    EXPECT_TRUE(first.valid);
    Reply again = consumeToken(kDisplay, t, kShell);
    EXPECT_TRUE(again.returnValue);
    EXPECT_FALSE(again.valid);
}

// Shown on behalf of anyone but the one it was issued to, it is refused,
// and spent.
TEST_F(AuthTest, ATokenIsBoundToWhoAskedForIt)
{
    start();
    boot();
    ASSERT_TRUE(setPasscode("pin", "7351").returnValue);
    std::string t = matchPasscode("7351", kShell).unlockToken;

    EXPECT_FALSE(consumeToken(kDisplay, t, "com.palm.app.email").valid);
    EXPECT_FALSE(consumeToken(kDisplay, t, kShell).valid);
}

TEST_F(AuthTest, ATokenExpires)
{
    start();
    boot();
    ASSERT_TRUE(setPasscode("pin", "7351").returnValue);

    std::string t = matchPasscode("7351", kShell).unlockToken;
    fakeplatform::advanceMs(UnlockToken::s_lifetimeMs - 1);
    EXPECT_TRUE(consumeToken(kDisplay, t, kShell).valid);

    t = matchPasscode("7351", kShell).unlockToken;
    fakeplatform::advanceMs(UnlockToken::s_lifetimeMs);
    EXPECT_FALSE(consumeToken(kDisplay, t, kShell).valid);
}

TEST_F(AuthTest, AWrongTokenSpendsNothing)
{
    start();
    boot();
    ASSERT_TRUE(setPasscode("pin", "7351").returnValue);
    std::string t = matchPasscode("7351", kShell).unlockToken;

    std::string guess = t;
    guess[0] = guess[0] == 'a' ? 'b' : 'a';
    EXPECT_FALSE(consumeToken(kDisplay, guess, kShell).valid);
    EXPECT_FALSE(consumeToken(kDisplay, "", kShell).valid);
    EXPECT_TRUE(consumeToken(kDisplay, t, kShell).valid);
}

TEST_F(AuthTest, OnlyOneTokenIsOutstanding)
{
    start();
    boot();
    ASSERT_TRUE(setPasscode("pin", "7351").returnValue);
    std::string first = matchPasscode("7351", kShell).unlockToken;
    std::string second = matchPasscode("7351", kShell).unlockToken;
    EXPECT_FALSE(consumeToken(kDisplay, first, kShell).valid);
    EXPECT_TRUE(consumeToken(kDisplay, second, kShell).valid);
}

// Only the display manager spends a token to unlock; anyone else is told
// no, and does not spend it for the one it belongs to.
TEST_F(AuthTest, OnlyTheDisplayManagerUnlocks)
{
    start();
    boot();
    ASSERT_TRUE(setPasscode("pin", "7351").returnValue);
    std::string t = matchPasscode("7351", kShell).unlockToken;

    for (const char* who : { kShell, "com.palm.app.email", kFace, "", "com.palm.display.x" }) {
        Reply r = consumeToken(who, t, kShell);
        EXPECT_FALSE(r.returnValue) << who;
        EXPECT_EQ(r.errorCode, Security::FailureNotAllowed) << who;
    }
    EXPECT_TRUE(consumeToken(kDisplay, t, kShell).valid);
}

TEST_F(AuthTest, EnrolmentIsForTheBiometricServices)
{
    start();
    boot();
    ASSERT_TRUE(setPasscode("pin", "7351").returnValue);
    const char* settings = "org.webosports.app.settings";

    std::string t = matchPasscode("7351", settings).unlockToken;
    EXPECT_EQ(consumeToken(kDisplay, t, settings, "enroll").errorCode, Security::FailureNotAllowed);
    EXPECT_EQ(consumeToken(kFace, t, settings, "unlock").errorCode, Security::FailureNotAllowed);
    EXPECT_TRUE(consumeToken(kFace, t, settings, "enroll").valid);

    t = matchPasscode("7351", settings).unlockToken;
    EXPECT_TRUE(consumeToken(kFinger, t, settings, "enroll").valid);
}

TEST_F(AuthTest, ANewPasscodeVoidsTheToken)
{
    start();
    boot();
    ASSERT_TRUE(setPasscode("pin", "7351").returnValue);
    std::string t = matchPasscode("7351", kShell).unlockToken;
    ASSERT_TRUE(setPasscode("pin", "2468").returnValue);
    EXPECT_FALSE(consumeToken(kDisplay, t, kShell).valid);
}

// No name to bind it to, or no random bytes: the match stands, no token.
TEST_F(AuthTest, NoTokenWithoutANameOrRandomness)
{
    start();
    boot();
    ASSERT_TRUE(setPasscode("pin", "7351").returnValue);

    Reply anon = matchPasscode("7351", "");
    EXPECT_TRUE(anon.returnValue);
    EXPECT_TRUE(anon.unlockToken.empty());

    fakeplatform::failRandom(true);
    Reply r = matchPasscode("7351", kShell);
    EXPECT_TRUE(r.returnValue);
    EXPECT_TRUE(r.unlockToken.empty());
    EXPECT_FALSE(consumeToken(kDisplay, "00000000000000000000000000000000", kShell).valid);
}

TEST_F(AuthTest, MalformedConsumeRequests)
{
    start();
    boot();
    const char* payloads[] = {
        "{}", "[]", "not json", "{\"token\":\"ab\"}", "{\"token\":\"ab\",\"requester\":\"x\"}",
        "{\"token\":\"ab\",\"requester\":\"x\",\"purpose\":\"wipe\"}",
        "{\"token\":1,\"requester\":\"x\",\"purpose\":\"unlock\"}",
        "{\"token\":\"ab\",\"requester\":null,\"purpose\":\"unlock\"}",
    };
    for (const char* p : payloads) {
        Reply r = callAuthAs("consumeUnlockToken", p, kDisplay);
        EXPECT_TRUE(r.ok) << p;
        EXPECT_FALSE(r.returnValue) << p;
        EXPECT_EQ(r.errorCode, Security::FailureBadRequest) << p;
    }
}

// The token methods are on the modern name alone.
TEST_F(AuthTest, TokenMethodsOnlyOnTheModernName)
{
    start();
    boot();
    for (const char* m : { "consumeUnlockToken", "issueBiometricToken", "reportBiometricFailure" }) {
        EXPECT_FALSE(fakebus::callMethod("com.palm.systemmanager", "/", m, "{}", kDisplay).found) << m;
        EXPECT_TRUE(fakebus::callMethod("com.webos.service.auth", "/", m, "{}", kDisplay).found) << m;
    }
}
