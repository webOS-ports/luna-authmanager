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

// The EAS policy side: db8's replies, the device-policy record, the watch,
// and what a policy does to passcodes and retries.

#include "fixture.h"

#include <algorithm>

namespace {

const char* const kEasPolicy =
    "{\"returnValue\":true,\"results\":[{\"_id\":\"eas1\",\"_rev\":5,"
    "\"_kind\":\"com.palm.eas.policy:1\",\"devicePasswordEnabled\":true,"
    "\"minDevicePasswordLength\":4,\"maxDevicePasswordFailedAttempts\":3}]}";

const char* const kDevicePolicyEnforced =
    "{\"returnValue\":true,\"results\":[{\"_id\":\"dev1\",\"_rev\":3,"
    "\"_kind\":\"com.palm.securitypolicy.device:1\",\"devicePasswordEnabled\":true,"
    "\"minDevicePasswordLength\":4,\"maxDevicePasswordFailedAttempts\":3,"
    "\"status\":{\"enforced\":true,\"retriesLeft\":3}}]}";

const char* const kSaved = "{\"returnValue\":true,\"results\":[{\"id\":\"dev1\",\"rev\":7}]}";

bool wasCancelled(LSMessageToken t)
{
    auto c = fakebus::cancelled();
    return std::find(c.begin(), c.end(), t) != c.end();
}

} // namespace

// An error is not "no device policy": a default one written over it would
// be a second record, and would reset the retry count.
TEST_F(AuthTest, DbErrorDoesNotWriteADefaultPolicy)
{
    start();
    ASSERT_TRUE(replyLast("palm://com.palm.db/del", kDeleted));
    ASSERT_TRUE(replyLast("palm://com.palm.db/find",
        "{\"returnValue\":false,\"errorCode\":-3970,\"errorText\":\"db: kind not registered\"}"));
    EXPECT_TRUE(fakebus::callsTo("palm://com.palm.db/put").empty());
    EXPECT_TRUE(fakebus::callsTo("palm://com.palm.db/merge").empty());
    // ...and the security policies are not asked for on top of nothing.
    EXPECT_EQ(fakebus::callsTo("palm://com.palm.db/find").size(), 1u);
}

TEST_F(AuthTest, ResultsThatAreNotAnArrayDoNotAbort)
{
    start();
    ASSERT_TRUE(replyLast("palm://com.palm.db/del", kDeleted));
    ASSERT_TRUE(replyLast("palm://com.palm.db/find", "{\"returnValue\":true,\"results\":\"x\"}"));
    EXPECT_TRUE(fakebus::callsTo("palm://com.palm.db/put").empty());

    restart();
    ASSERT_TRUE(replyLast("palm://com.palm.db/del", kDeleted));
    ASSERT_TRUE(replyLast("palm://com.palm.db/find", kNoDevicePolicy));
    ASSERT_TRUE(replyLast("palm://com.palm.db/find", "{\"returnValue\":true,\"results\":{\"a\":1}}"));
    ASSERT_TRUE(replyLast("palm://com.palm.db/find", "{\"returnValue\":true,\"results\":7}"));
}

// No device record yet, and the EAS policies arrive before the first put is
// answered: one put, then a merge under the id it got.
TEST_F(AuthTest, OneDevicePolicyPutAtATime)
{
    start();
    boot(kNoDevicePolicy, kEasPolicy);
    ASSERT_EQ(fakebus::callsTo("palm://com.palm.db/put").size(), 1u);
    EXPECT_TRUE(fakebus::callsTo("palm://com.palm.db/merge").empty());

    ASSERT_TRUE(replyLast("palm://com.palm.db/put", kSaved));
    EXPECT_EQ(fakebus::callsTo("palm://com.palm.db/put").size(), 1u);
    auto merges = fakebus::callsTo("palm://com.palm.db/merge");
    ASSERT_EQ(merges.size(), 1u);
    EXPECT_NE(merges[0].payload.find("\"_id\": \"dev1\""), std::string::npos) << merges[0].payload;
    EXPECT_NE(merges[0].payload.find("\"devicePasswordEnabled\": true"), std::string::npos);

    // The watch is set once the last save is answered.
    EXPECT_TRUE(fakebus::callsTo("palm://com.palm.db/watch").empty());
    ASSERT_TRUE(replyLast("palm://com.palm.db/merge", kSaved));
    EXPECT_EQ(fakebus::callsTo("palm://com.palm.db/watch").size(), 1u);
}

TEST_F(AuthTest, FiredWatchIsCancelledAndPoliciesAskedFor)
{
    start();
    boot();
    ASSERT_TRUE(replyLast("palm://com.palm.db/put", kSaved));
    auto watches = fakebus::callsTo("palm://com.palm.db/watch");
    ASSERT_FALSE(watches.empty());
    const LSMessageToken t = watches.back().token;
    const size_t finds = fakebus::callsTo("palm://com.palm.db/find").size();

    ASSERT_TRUE(fakebus::reply(t, "{\"returnValue\":true}"));
    EXPECT_FALSE(wasCancelled(t)) << "the first reply only says the watch is set";

    ASSERT_TRUE(fakebus::reply(t, "{\"returnValue\":true,\"fired\":true}"));
    EXPECT_TRUE(wasCancelled(t));
    EXPECT_EQ(fakebus::callsTo("palm://com.palm.db/find").size(), finds + 1);
}

TEST_F(AuthTest, FailedWatchIsCancelled)
{
    start();
    boot();
    ASSERT_TRUE(replyLast("palm://com.palm.db/put", kSaved));
    auto watches = fakebus::callsTo("palm://com.palm.db/watch");
    ASSERT_FALSE(watches.empty());
    ASSERT_TRUE(fakebus::reply(watches.back().token, "{\"returnValue\":false,\"errorCode\":-1}"));
    EXPECT_TRUE(wasCancelled(watches.back().token));
}

// -1 from a policy is not 4294967295: a minimum length nobody can meet, or
// a retry limit that is really unlimited.
TEST_F(AuthTest, NegativePolicyValuesAreClamped)
{
    start();
    boot(kNoDevicePolicy,
         "{\"returnValue\":true,\"results\":[{\"_id\":\"eas1\",\"_rev\":5,"
         "\"_kind\":\"com.palm.eas.policy:1\",\"devicePasswordEnabled\":true,"
         "\"minDevicePasswordLength\":-1,\"maxDevicePasswordFailedAttempts\":-1}]}");
    const EASPolicy* p = EASPolicyManager::instance()->getPolicy();
    ASSERT_NE(p, nullptr);
    EXPECT_EQ(p->minLength(), 0u);
    EXPECT_EQ(p->maxRetries(), 0u);
    EXPECT_TRUE(setPasscode("pin", "739164").returnValue);
}

TEST_F(AuthTest, RetriesLeftComeFromTheDeviceRecord)
{
    const char* dev = "{\"returnValue\":true,\"results\":[{\"_id\":\"dev1\",\"_rev\":3,"
        "\"_kind\":\"com.palm.securitypolicy.device:1\",\"devicePasswordEnabled\":true,"
        "\"minDevicePasswordLength\":4,\"maxDevicePasswordFailedAttempts\":3,"
        "\"status\":{\"enforced\":true,\"retriesLeft\":2}}]}";
    start();
    boot(dev, kEasPolicy);
    EXPECT_EQ(EASPolicyManager::instance()->retriesLeft(), 2u);
}

TEST_F(AuthTest, EnforcedPolicyWipesAfterItsLastRetry)
{
    start();
    boot(kDevicePolicyEnforced, kEasPolicy);
    ASSERT_TRUE(setPasscode("pin", "7351").returnValue);

    EXPECT_EQ(matchPasscode("0482").retriesLeft, 2);
    EXPECT_EQ(matchPasscode("0482").retriesLeft, 1);
    EXPECT_TRUE(fakebus::callsTo("palm://com.palm.storage/erase/Wipe").empty());
    EXPECT_EQ(matchPasscode("0482").retriesLeft, 0);

    auto wipes = fakebus::callsTo("palm://com.palm.storage/erase/Wipe");
    ASSERT_EQ(wipes.size(), 1u);
    EXPECT_TRUE(wipes[0].oneReply);
}

TEST_F(AuthTest, PolicyRulesComeOnTopOfTheBaseline)
{
    start();
    boot(kNoDevicePolicy,
         "{\"returnValue\":true,\"results\":[{\"_id\":\"eas1\",\"_rev\":5,"
         "\"_kind\":\"com.palm.eas.policy:1\",\"devicePasswordEnabled\":true,"
         "\"minDevicePasswordLength\":6,\"alphanumericDevicePasswordRequired\":true}]}");
    EXPECT_EQ(setPasscode("pin", "739164").errorCode, Security::FailureInvalidPassword);
    EXPECT_EQ(setPasscode("password", "a7b9").errorCode, Security::FailureMinLength);
    EXPECT_EQ(setPasscode("password", "abcdefg").errorCode, Security::FailureWeakPasswordSequence);
    EXPECT_EQ(setPasscode("password", "plumtree").errorCode, Security::FailureAlphaNumeric);
    EXPECT_TRUE(setPasscode("password", "plum7tree").returnValue);
    EXPECT_FALSE(EASPolicyManager::instance()->policyPending());
}
