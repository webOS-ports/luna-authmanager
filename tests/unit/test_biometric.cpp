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

// When a finger or face may stand in for the passcode: not before the
// passcode has been entered this boot, not 72 hours after it last was, not
// during a passcode lockout, and not after five rejected tries in a row -
// one budget, kept here and saved, not one per screen wake in the shell.

#include "fixture.h"

namespace {

const char* const kShell = "com.webos.surfacemanager-cardshell";
const char* const kDisplay = "com.palm.display";
const char* const kFace = "com.webos.service.faceunlock";
const char* const kFinger = "com.webos.service.fingerprint";

Reply issue(const char* factor, const char* caller = nullptr, const char* requester = kShell)
{
    if (!caller)
        caller = std::string(factor) == "face" ? kFace : kFinger;
    return callAuthAs("issueBiometricToken",
                      std::string("{\"factor\":\"") + factor + "\",\"requester\":\"" + requester + "\"}",
                      caller);
}

Reply reject(const char* factor, const char* caller = nullptr)
{
    if (!caller)
        caller = std::string(factor) == "face" ? kFace : kFinger;
    return callAuthAs("reportBiometricFailure", std::string("{\"factor\":\"") + factor + "\"}", caller);
}

bool lockModeSaysAllowed()
{
    Reply r = callAuth("getDeviceLockMode", "{}");
    EXPECT_TRUE(r.hasBiometricAllowed) << r.raw;
    return r.biometricAllowed;
}

} // namespace

TEST_F(AuthTest, ABiometricMatchEarnsAnUnlockOnlyToken)
{
    start();
    boot();
    ASSERT_TRUE(setPasscode("pin", "7351").returnValue);
    EXPECT_TRUE(lockModeSaysAllowed());

    Reply r = issue("face");
    ASSERT_TRUE(r.returnValue) << r.raw;
    EXPECT_EQ(r.unlockToken.size(), 32u);
    EXPECT_FALSE(consumeToken(kFace, r.unlockToken, kShell, "enroll").valid);

    r = issue("fingerprint");
    EXPECT_TRUE(consumeToken(kDisplay, r.unlockToken, kShell).valid);
}

TEST_F(AuthTest, NoBiometricWithoutAPasscode)
{
    start();
    boot();
    EXPECT_FALSE(lockModeSaysAllowed());
    Reply r = issue("face");
    EXPECT_FALSE(r.returnValue);
    EXPECT_TRUE(r.passcodeRequired);
    EXPECT_TRUE(r.unlockToken.empty());
}

TEST_F(AuthTest, NoBiometricBeforeThePasscodeAfterBoot)
{
    start();
    boot();
    ASSERT_TRUE(setPasscode("pin", "7351").returnValue);

    // A restart of the daemon is not a boot.
    restart();
    boot();
    EXPECT_TRUE(issue("face").returnValue);

    stop();
    fakeplatform::reboot();
    start();
    boot();
    EXPECT_FALSE(lockModeSaysAllowed());
    Reply r = issue("fingerprint");
    EXPECT_FALSE(r.returnValue);
    EXPECT_TRUE(r.passcodeRequired);

    ASSERT_TRUE(matchPasscode("7351", kShell).returnValue);
    EXPECT_TRUE(issue("fingerprint").returnValue);
}

// Without a boot id the boot cannot be told apart: no biometrics after a
// restart until the passcode.
TEST_F(AuthTest, NoBootIdNoBiometricAfterARestart)
{
    fakeplatform::setBootId("");
    start();
    boot();
    ASSERT_TRUE(setPasscode("pin", "7351").returnValue);
    restart();
    boot();
    EXPECT_FALSE(issue("face").returnValue);
}

TEST_F(AuthTest, FiveRejectionsInARowTakeThePasscode)
{
    start();
    boot();
    ASSERT_TRUE(setPasscode("pin", "7351").returnValue);

    for (int i = 1; i < 5; ++i)
        EXPECT_TRUE(reject(i % 2 ? "face" : "fingerprint").biometricAllowed) << i;
    fakebus::clearRecords();
    Reply last = reject("face");
    EXPECT_TRUE(last.returnValue);
    EXPECT_FALSE(last.biometricAllowed);
    EXPECT_FALSE(issue("fingerprint").returnValue);

    // Subscribers (the lock screen) hear of it.
    bool posted = false;
    for (const auto& p : fakebus::posts())
        if (p.method == "getDeviceLockMode" && p.payload.find("\"biometricAllowed\": false") != std::string::npos)
            posted = true;
    EXPECT_TRUE(posted);

    ASSERT_TRUE(matchPasscode("7351").returnValue);
    EXPECT_TRUE(issue("face").returnValue);
}

TEST_F(AuthTest, AMatchStartsTheRejectionsAgain)
{
    start();
    boot();
    ASSERT_TRUE(setPasscode("pin", "7351").returnValue);
    for (int i = 0; i < 4; ++i)
        reject("face");
    ASSERT_TRUE(issue("face").returnValue);
    for (int i = 0; i < 4; ++i)
        EXPECT_TRUE(reject("face").biometricAllowed);
}

TEST_F(AuthTest, TheRejectionsSurviveARestart)
{
    start();
    boot();
    ASSERT_TRUE(setPasscode("pin", "7351").returnValue);
    for (int i = 0; i < 3; ++i)
        reject("face");
    restart();
    boot();
    reject("face");
    EXPECT_FALSE(reject("face").biometricAllowed);
}

TEST_F(AuthTest, APasscodeLockoutHoldsBiometricsOff)
{
    start();
    boot();
    ASSERT_TRUE(setPasscode("pin", "7351").returnValue);
    for (int i = 0; i < 5; ++i)
        matchPasscode("0482");
    EXPECT_FALSE(issue("face").returnValue);
    fakeplatform::advanceMs(30 * 1000);
    EXPECT_TRUE(issue("face").returnValue);
}

TEST_F(AuthTest, SeventyTwoHoursAfterThePasscodeItIsNeededAgain)
{
    start();
    boot();
    ASSERT_TRUE(setPasscode("pin", "7351").returnValue);
    fakeplatform::advanceMs(Security::s_biometricPasscodeMaxAgeMs - 1000);
    EXPECT_TRUE(issue("face").returnValue);
    fakeplatform::advanceMs(1000);
    EXPECT_FALSE(issue("face").returnValue);
    ASSERT_TRUE(matchPasscode("7351").returnValue);
    EXPECT_TRUE(issue("face").returnValue);
}

// Only a factor's own service may say it matched or failed.
TEST_F(AuthTest, OnlyTheFactorsServiceMaySpeakForIt)
{
    start();
    boot();
    ASSERT_TRUE(setPasscode("pin", "7351").returnValue);

    for (const char* who : { kShell, kDisplay, kFinger, "com.palm.app.email", "" }) {
        Reply r = issue("face", who);
        EXPECT_FALSE(r.returnValue) << who;
        EXPECT_EQ(r.errorCode, Security::FailureNotAllowed) << who;
        EXPECT_TRUE(r.unlockToken.empty()) << who;
    }
    EXPECT_EQ(issue("fingerprint", kFace).errorCode, Security::FailureNotAllowed);

    for (int i = 0; i < 10; ++i)
        EXPECT_EQ(reject("face", kShell).errorCode, Security::FailureNotAllowed);
    EXPECT_TRUE(issue("face").returnValue);
}

TEST_F(AuthTest, ABiometricTokenIsBoundToTheRequester)
{
    start();
    boot();
    ASSERT_TRUE(setPasscode("pin", "7351").returnValue);
    std::string t = issue("face", kFace, kShell).unlockToken;
    EXPECT_FALSE(consumeToken(kDisplay, t, "com.palm.app.email").valid);
}

TEST_F(AuthTest, MalformedBiometricRequests)
{
    start();
    boot();
    ASSERT_TRUE(setPasscode("pin", "7351").returnValue);
    const char* payloads[] = {
        "{}", "[]", "null", "{\"factor\":\"iris\",\"requester\":\"x\"}", "{\"factor\":\"face\"}",
        "{\"factor\":\"face\",\"requester\":\"\"}", "{\"factor\":1,\"requester\":\"x\"}",
    };
    for (const char* p : payloads) {
        Reply r = callAuthAs("issueBiometricToken", p, kFace);
        EXPECT_EQ(r.errorCode, Security::FailureBadRequest) << p;
    }
    for (const char* p : { "{}", "{\"factor\":\"iris\"}", "{\"factor\":null}", "x" }) {
        Reply r = callAuthAs("reportBiometricFailure", p, kFace);
        EXPECT_EQ(r.errorCode, Security::FailureBadRequest) << p;
    }
    EXPECT_TRUE(issue("face").returnValue);
}

// Removing the passcode takes biometrics with it, even right after it was
// entered.
TEST_F(AuthTest, NoBiometricOnceThePasscodeIsRemoved)
{
    start();
    boot();
    ASSERT_TRUE(setPasscode("pin", "7351").returnValue);
    ASSERT_TRUE(issue("face").returnValue);
    ASSERT_TRUE(setPasscode("none", "").returnValue);
    EXPECT_FALSE(lockModeSaysAllowed());
    EXPECT_FALSE(issue("face").returnValue);
}
