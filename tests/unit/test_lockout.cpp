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

// Wrong passcodes: five free, then a lockout that doubles each time, from 30
// seconds up to an hour, whether or not an EAS policy is in force.

#include "fixture.h"

namespace {

const char* const kPolicyNoRetryLimit =
    "{\"returnValue\":true,\"results\":[{\"_id\":\"eas1\",\"_rev\":5,"
    "\"_kind\":\"com.palm.eas.policy:1\",\"devicePasswordEnabled\":true,"
    "\"minDevicePasswordLength\":4,\"maxDevicePasswordFailedAttempts\":0}]}";

} // namespace

TEST_F(AuthTest, FiveWrongThenLockedOut)
{
    start();
    boot();
    ASSERT_TRUE(setPasscode("pin", "7351").returnValue);

    for (int i = 1; i < 5; ++i) {
        Reply r = matchPasscode("0482");
        EXPECT_FALSE(r.lockedOut) << "try " << i;
        EXPECT_EQ(r.retriesLeft, 5 - i);
    }

    Reply fifth = matchPasscode("0482");
    EXPECT_FALSE(fifth.returnValue);
    EXPECT_TRUE(fifth.lockedOut);
    EXPECT_EQ(fifth.lockoutSeconds, 30);
    EXPECT_EQ(fifth.retriesLeft, 0);

    // During the lockout even the right code is refused, unchecked.
    fakeplatform::advanceMs(29 * 1000);
    Reply during = matchPasscode("7351");
    EXPECT_FALSE(during.returnValue);
    EXPECT_TRUE(during.lockedOut);
    EXPECT_EQ(during.lockoutSeconds, 1);

    fakeplatform::advanceMs(1000);
    EXPECT_TRUE(matchPasscode("7351").returnValue);
}

TEST_F(AuthTest, EachLockoutDoublesUpToAnHour)
{
    start();
    boot();
    ASSERT_TRUE(setPasscode("pin", "7351").returnValue);
    for (int i = 0; i < 4; ++i)
        matchPasscode("0482");

    int expected[] = { 30, 60, 120, 240, 480, 960, 1920, 3600, 3600, 3600 };
    for (int seconds : expected) {
        Reply r = matchPasscode("0482");
        ASSERT_TRUE(r.lockedOut);
        EXPECT_EQ(r.lockoutSeconds, seconds);
        // The lockout runs out, and the next wrong code starts the next one.
        fakeplatform::advanceMs((uint64_t) seconds * 1000);
    }
}

TEST_F(AuthTest, RightCodeStartsTheCountAgain)
{
    start();
    boot();
    ASSERT_TRUE(setPasscode("pin", "7351").returnValue);
    for (int i = 0; i < 4; ++i)
        matchPasscode("0482");
    ASSERT_TRUE(matchPasscode("7351").returnValue);
    for (int i = 0; i < 4; ++i)
        EXPECT_FALSE(matchPasscode("0482").lockedOut);
}

TEST_F(AuthTest, NewPasscodeStartsTheCountAgain)
{
    start();
    boot();
    ASSERT_TRUE(setPasscode("pin", "7351").returnValue);
    for (int i = 0; i < 5; ++i)
        matchPasscode("0482");
    ASSERT_TRUE(setPasscode("pin", "2468").returnValue);
    EXPECT_TRUE(matchPasscode("2468").returnValue);
}

// Without a retry limit an active policy used to mean unlimited tries.
TEST_F(AuthTest, LockoutAlsoUnderAPolicyWithoutRetryLimit)
{
    start();
    boot(kNoDevicePolicy, kPolicyNoRetryLimit);
    ASSERT_TRUE(replyLast("palm://com.palm.db/put",
        "{\"returnValue\":true,\"results\":[{\"id\":\"dev1\",\"rev\":7}]}"));
    ASSERT_TRUE(setPasscode("pin", "7351").returnValue);
    ASSERT_FALSE(EASPolicyManager::instance()->policyPending());

    bool lockedOut = false;
    for (int i = 0; i < 5; ++i)
        lockedOut = matchPasscode("0482").lockedOut;
    EXPECT_TRUE(lockedOut);
}

TEST_F(AuthTest, NoPasscodeCountsNothing)
{
    start();
    boot();
    for (int i = 0; i < 10; ++i) {
        Reply r = matchPasscode("0482");
        EXPECT_FALSE(r.returnValue);
        EXPECT_FALSE(r.lockedOut);
    }
}
