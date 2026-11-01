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

// Changing or removing a passcode takes the one set now, checked here and
// counted like an unlock try - not only by Settings before it calls.

#include "fixture.h"

#include <unistd.h>

namespace {

const char* const kEasPolicy =
    "{\"returnValue\":true,\"results\":[{\"_id\":\"eas1\",\"_rev\":5,"
    "\"_kind\":\"com.palm.eas.policy:1\",\"devicePasswordEnabled\":true,"
    "\"minDevicePasswordLength\":4,\"maxDevicePasswordFailedAttempts\":0}]}";

} // namespace

TEST_F(AuthTest, FirstPasscodeNeedsNoCurrentOne)
{
    start();
    boot();
    EXPECT_FALSE(Security::instance()->currentPasscodeRequired());
    EXPECT_TRUE(setPasscodeWith("pin", "7351", nullptr).returnValue);
    EXPECT_TRUE(Security::instance()->currentPasscodeRequired());
}

TEST_F(AuthTest, ChangingNeedsTheCurrentPasscode)
{
    start();
    boot();
    ASSERT_TRUE(setPasscode("pin", "7351").returnValue);

    Reply r = setPasscodeWith("pin", "2468", nullptr);
    EXPECT_FALSE(r.returnValue);
    EXPECT_EQ(r.errorCode, Security::FailureCurrentPasscode);
    r = setPasscodeWith("pin", "2468", "");
    EXPECT_EQ(r.errorCode, Security::FailureCurrentPasscode);
    EXPECT_TRUE(matchPasscode("7351").returnValue);
    EXPECT_FALSE(matchPasscode("2468").returnValue);

    EXPECT_TRUE(setPasscodeWith("pin", "2468", "7351").returnValue);
    EXPECT_TRUE(matchPasscode("2468").returnValue);
}

TEST_F(AuthTest, RemovingNeedsTheCurrentPasscode)
{
    start();
    boot();
    ASSERT_TRUE(setPasscode("pin", "7351").returnValue);

    EXPECT_EQ(setPasscodeWith("none", "", nullptr).errorCode, Security::FailureCurrentPasscode);
    EXPECT_EQ(setPasscodeWith("none", "", "0482").errorCode, Security::FailureCurrentPasscode);
    EXPECT_EQ(Security::instance()->getLockMode(), "pin");
    EXPECT_EQ(::access(path(".passcode").c_str(), F_OK), 0);

    EXPECT_TRUE(setPasscodeWith("none", "", "7351").returnValue);
    EXPECT_EQ(Security::instance()->getLockMode(), "none");
}

TEST_F(AuthTest, AWrongCurrentPasscodeIsAWrongTry)
{
    start();
    boot();
    ASSERT_TRUE(setPasscode("pin", "7351").returnValue);

    Reply r = setPasscodeWith("pin", "2468", "0482");
    EXPECT_FALSE(r.lockedOut);
    EXPECT_EQ(r.retriesLeft, 4);
    for (int i = 0; i < 3; ++i)
        (void) setPasscodeWith("none", "", "0482");
    r = setPasscodeWith("pin", "2468", "0482");
    EXPECT_TRUE(r.lockedOut);
    EXPECT_EQ(r.lockoutSeconds, 30);
    // The lock screen is held off by the same count.
    EXPECT_TRUE(matchPasscode("7351").lockedOut);
}

// The new passcode's rules come first, so a weak one costs no try.
TEST_F(AuthTest, AWeakNewPasscodeCostsNoTry)
{
    start();
    boot();
    ASSERT_TRUE(setPasscode("pin", "7351").returnValue);
    EXPECT_EQ(setPasscodeWith("pin", "1234", "0482").errorCode, Security::FailureWeakPasswordSequence);
    EXPECT_EQ(matchPasscode("0482").retriesLeft, 4);
}

TEST_F(AuthTest, CurrentPasscodeMustBeAString)
{
    start();
    boot();
    ASSERT_TRUE(setPasscode("pin", "7351").returnValue);
    Reply r = callAuth("setDevicePasscode", "{\"lockMode\":\"pin\",\"passCode\":\"2468\",\"currentPasscode\":7351}");
    EXPECT_EQ(r.errorCode, Security::FailureBadRequest);
    EXPECT_TRUE(matchPasscode("7351").returnValue);
}

TEST_F(AuthTest, AlsoOnTheModernName)
{
    start();
    boot();
    ASSERT_TRUE(setPasscode("pin", "7351").returnValue);
    Reply r = callAuth("setDevicePasscode", "{\"lockMode\":\"none\"}", "com.webos.service.auth");
    EXPECT_EQ(r.errorCode, Security::FailureCurrentPasscode);
    EXPECT_EQ(Security::instance()->getLockMode(), "pin");
}

// A pending EAS policy that requires a password lets the email app have the
// owner set a compliant one without the old - but not remove it.
TEST_F(AuthTest, APendingPolicyMayReplaceButNotRemove)
{
    start();
    boot();
    ASSERT_TRUE(setPasscode("pin", "7351").returnValue);

    restart();
    boot(kNoDevicePolicy, kEasPolicy);
    ASSERT_TRUE(replyLast("palm://com.palm.db/put",
        "{\"returnValue\":true,\"results\":[{\"id\":\"dev1\",\"rev\":7}]}"));
    ASSERT_TRUE(EASPolicyManager::instance()->policyPending());
    EXPECT_FALSE(Security::instance()->currentPasscodeRequired());

    EXPECT_FALSE(setPasscodeWith("none", "", nullptr).returnValue);
    EXPECT_EQ(Security::instance()->getLockMode(), "pin");

    EXPECT_TRUE(setPasscodeWith("pin", "2468", nullptr).returnValue);
    ASSERT_FALSE(EASPolicyManager::instance()->policyPending());
    // Enforced now: back to needing the current one.
    EXPECT_TRUE(Security::instance()->currentPasscodeRequired());
    EXPECT_EQ(setPasscodeWith("pin", "9413", nullptr).errorCode, Security::FailureCurrentPasscode);
}
