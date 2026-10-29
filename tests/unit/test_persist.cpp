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

// The lockout outlives the daemon and the boot: the count, the deadline and
// the biometric state are in authStateDir()/lockout, 0600 in a 0700
// directory, written whole or not at all.

#include "fixture.h"

#include <sys/stat.h>
#include <unistd.h>

#include <fstream>

namespace {

void failFive()
{
    for (int i = 0; i < 5; ++i)
        matchPasscode("0482");
}

} // namespace

TEST_F(AuthTest, TheStateFileIsPrivate)
{
    start();
    boot();
    ASSERT_TRUE(setPasscode("pin", "7351").returnValue);
    matchPasscode("0482");

    struct stat st;
    ASSERT_EQ(::lstat(path("state").c_str(), &st), 0);
    EXPECT_TRUE(S_ISDIR(st.st_mode));
    EXPECT_EQ(st.st_mode & 07777, 0700u);
    ASSERT_EQ(::lstat(path("state/lockout").c_str(), &st), 0);
    EXPECT_TRUE(S_ISREG(st.st_mode));
    EXPECT_EQ(st.st_mode & 07777, 0600u);
    EXPECT_NE(::access(path("state/lockout.tmp").c_str(), F_OK), 0);
    EXPECT_NE(readFile(path("state/lockout")).find("\"failures\": 1"), std::string::npos);
}

TEST_F(AuthTest, TheCountSurvivesARestart)
{
    start();
    boot();
    ASSERT_TRUE(setPasscode("pin", "7351").returnValue);
    for (int i = 0; i < 4; ++i)
        matchPasscode("0482");

    restart();
    boot();
    Reply r = matchPasscode("0482");
    EXPECT_TRUE(r.lockedOut);
    EXPECT_EQ(r.lockoutSeconds, 30);
}

TEST_F(AuthTest, ALockoutSurvivesARestart)
{
    start();
    boot();
    ASSERT_TRUE(setPasscode("pin", "7351").returnValue);
    failFive();
    fakeplatform::advanceMs(10 * 1000);

    restart();
    boot();
    Reply r = matchPasscode("7351");
    EXPECT_FALSE(r.returnValue);
    EXPECT_TRUE(r.lockedOut);
    EXPECT_EQ(r.lockoutSeconds, 20);

    fakeplatform::advanceMs(20 * 1000);
    EXPECT_TRUE(matchPasscode("7351").returnValue);
}

TEST_F(AuthTest, ALockoutSurvivesAReboot)
{
    start();
    boot();
    ASSERT_TRUE(setPasscode("pin", "7351").returnValue);
    failFive();
    fakeplatform::advanceMs(10 * 1000);

    stop();
    fakeplatform::reboot();
    start();
    boot();
    Reply r = matchPasscode("7351");
    EXPECT_TRUE(r.lockedOut);
    EXPECT_EQ(r.lockoutSeconds, 20);
    fakeplatform::advanceMs(20 * 1000);
    EXPECT_TRUE(matchPasscode("7351").returnValue);
}

// After a reboot that outlasted the lockout, the next wrong code starts the
// next, longer one: the count did not start again.
TEST_F(AuthTest, ARebootDoesNotStartTheCountAgain)
{
    start();
    boot();
    ASSERT_TRUE(setPasscode("pin", "7351").returnValue);
    failFive();

    stop();
    fakeplatform::reboot();
    fakeplatform::setRealtimeMs(fakeplatform::realtimeNowMs() + 31 * 1000);
    start();
    boot();
    Reply r = matchPasscode("0482");
    EXPECT_TRUE(r.lockedOut);
    EXPECT_EQ(r.lockoutSeconds, 60);
}

// A clock set back (a flat RTC battery, by hand) owes the whole lockout,
// not an hour more and not nothing.
TEST_F(AuthTest, AClockSetBackOwesTheWholeLockout)
{
    start();
    boot();
    ASSERT_TRUE(setPasscode("pin", "7351").returnValue);
    failFive();
    fakeplatform::advanceMs(20 * 1000);

    stop();
    fakeplatform::reboot();
    fakeplatform::setRealtimeMs(946684800000ULL);   // 2000-01-01
    start();
    boot();
    Reply r = matchPasscode("7351");
    EXPECT_TRUE(r.lockedOut);
    EXPECT_EQ(r.lockoutSeconds, 30);
}

// Within a boot the monotonic deadline holds, whatever the wall clock says.
TEST_F(AuthTest, TheWallClockDoesNotEndALockoutWithinABoot)
{
    start();
    boot();
    ASSERT_TRUE(setPasscode("pin", "7351").returnValue);
    failFive();
    fakeplatform::setRealtimeMs(fakeplatform::realtimeNowMs() + 24ULL * 3600 * 1000);

    restart();
    boot();
    EXPECT_TRUE(matchPasscode("7351").lockedOut);
}

// A deadline written further off than any lockout is long is cut to it.
TEST_F(AuthTest, AnOverlongDeadlineIsCut)
{
    start();
    boot();
    ASSERT_TRUE(setPasscode("pin", "7351").returnValue);
    stop();
    {
        std::ofstream f(path("state/lockout"));
        f << "{\"version\":1,\"bootId\":\"other\",\"failures\":9,\"lockedUntilMono\":0,"
             "\"lockedUntilWall\":99999999999999,\"lockoutMs\":99999999999,\"savedAtWall\":0}";
    }
    start();
    boot();
    Reply r = matchPasscode("7351");
    EXPECT_TRUE(r.lockedOut);
    EXPECT_EQ(r.lockoutSeconds, (int) (Security::s_maxLockoutMs / 1000));
}

TEST_F(AuthTest, AnUnreadableStateFileSpendsTheFreeTries)
{
    start();
    boot();
    ASSERT_TRUE(setPasscode("pin", "7351").returnValue);
    stop();
    {
        std::ofstream f(path("state/lockout"));
        f << "{\"failures\":";
    }
    start();
    boot();
    EXPECT_FALSE(matchPasscode("7351").lockedOut);   // no lockout from it alone
    ASSERT_TRUE(matchPasscode("7351").returnValue);
    stop();
    {
        std::ofstream f(path("state/lockout"));
        f << "[1,2";
    }
    start();
    boot();
    Reply r = matchPasscode("0482");
    EXPECT_TRUE(r.lockedOut);
}

TEST_F(AuthTest, ARightCodeClearsTheSavedCount)
{
    start();
    boot();
    ASSERT_TRUE(setPasscode("pin", "7351").returnValue);
    for (int i = 0; i < 4; ++i)
        matchPasscode("0482");
    ASSERT_TRUE(matchPasscode("7351").returnValue);

    restart();
    boot();
    for (int i = 0; i < 4; ++i)
        EXPECT_FALSE(matchPasscode("0482").lockedOut);
}

// Matching does not depend on the state being saved.
TEST_F(AuthTest, AnUnwritableStateDirIsNotFatal)
{
    {
        std::ofstream f(path("state"));
        f << "not a directory";
    }
    start();
    boot();
    ASSERT_TRUE(setPasscode("pin", "7351").returnValue);
    EXPECT_FALSE(matchPasscode("0482").returnValue);
    EXPECT_TRUE(matchPasscode("7351").returnValue);
}

// A link in place of the state file is not followed: it reads as
// unreadable, and costs the free tries.
TEST_F(AuthTest, AStateFileLinkIsNotFollowed)
{
    start();
    boot();
    ASSERT_TRUE(setPasscode("pin", "7351").returnValue);
    stop();
    {
        std::ofstream f(path("elsewhere"));
        f << "{\"version\":1,\"failures\":0}";
    }
    ASSERT_EQ(::unlink(path("state/lockout").c_str()), 0);
    ASSERT_EQ(::symlink(path("elsewhere").c_str(), path("state/lockout").c_str()), 0);
    start();
    boot();
    EXPECT_TRUE(matchPasscode("0482").lockedOut);
}
