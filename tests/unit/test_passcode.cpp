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

// Setting and matching a passcode: the stored format, the move from the
// format luna-sysmgr wrote, the strength rules, and the file handling.

#include "fixture.h"

#include <signal.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <unistd.h>

#include <vector>

namespace {

json_object* passcodeJson(const std::string& file)
{
    return json_object_from_file(file.c_str());
}

std::string storedValue(const std::string& file, const char* mode)
{
    json_object* o = passcodeJson(file);
    if (!o)
        return "";
    json_object* v = nullptr;
    std::string out;
    if (json_object_object_get_ex(o, mode, &v))
        out = json_object_get_string(v);
    json_object_put(o);
    return out;
}

int storedVersion(const std::string& file)
{
    json_object* o = passcodeJson(file);
    if (!o)
        return -1;
    json_object* v = nullptr;
    int out = json_object_object_get_ex(o, "version", &v) ? json_object_get_int(v) : 0;
    json_object_put(o);
    return out;
}

// Codes whose SHA-1 starts with a NUL byte: the ones luna-sysmgr's format
// stored as an empty string.
std::vector<std::string> nulHashCodes(size_t n)
{
    std::vector<std::string> out;
    for (unsigned i = 0; out.size() < n && i < 1000000; ++i) {
        std::string c = "k" + std::to_string(i * 7919u) + "q";
        if (legacyHash(c).empty())
            out.push_back(c);
    }
    return out;
}

} // namespace

TEST_F(AuthTest, StoresAVersionedSaltedHash)
{
    start();
    boot();
    ASSERT_TRUE(setPasscode("pin", "7351").returnValue);

    EXPECT_EQ(storedVersion(path(".passcode")), 2);
    const std::string h = storedValue(path(".passcode"), "pin");
    EXPECT_EQ(h.compare(0, 3, "$y$"), 0) << h;
    EXPECT_EQ(h.find("7351"), std::string::npos);

    struct stat st;
    ASSERT_EQ(::stat(path(".passcode").c_str(), &st), 0);
    EXPECT_EQ(st.st_mode & 0777, 0600u);

    // A fresh salt every time: the same code does not give the same hash.
    ASSERT_TRUE(setPasscode("pin", "7351").returnValue);
    EXPECT_NE(storedValue(path(".passcode"), "pin"), h);
}

TEST_F(AuthTest, MatchesOnlyTheRightCode)
{
    start();
    boot();
    ASSERT_TRUE(setPasscode("password", "correct horse").returnValue);
    EXPECT_TRUE(matchPasscode("correct horse").returnValue);
    EXPECT_FALSE(matchPasscode("correct horsf").returnValue);
    EXPECT_FALSE(matchPasscode("").returnValue);

    restart();
    boot();
    EXPECT_EQ(Security::instance()->getLockMode(), "password");
    EXPECT_TRUE(matchPasscode("correct horse").returnValue);
}

// luna-sysmgr's format cut the hash at its first NUL byte: any code whose
// hash started with one unlocked a device whose code's hash did too.
TEST_F(AuthTest, HashesStartingWithNulDoNotMatchEachOther)
{
    std::vector<std::string> codes = nulHashCodes(8);
    ASSERT_EQ(codes.size(), 8u);

    start();
    boot();
    // The first of them the strength rules accept.
    size_t set = 0;
    while (set < codes.size() && !setPasscode("password", codes[set]).returnValue)
        ++set;
    ASSERT_LT(set, codes.size());
    const std::string& other = codes[(set + 1) % codes.size()];

    EXPECT_FALSE(matchPasscode(other).returnValue) << other << " unlocks " << codes[set];
    EXPECT_TRUE(matchPasscode(codes[set]).returnValue);
}

TEST_F(AuthTest, LegacyFileMatchesAndIsMovedToVersion2)
{
    writeLegacyPasscode(dir, "pin", "7351");
    start();
    boot();
    EXPECT_EQ(Security::instance()->getLockMode(), "pin");

    EXPECT_FALSE(matchPasscode("7352").returnValue);
    EXPECT_EQ(storedVersion(path(".passcode")), 0) << "rewritten on a wrong code";

    EXPECT_TRUE(matchPasscode("7351").returnValue);
    EXPECT_EQ(storedVersion(path(".passcode")), 2);
    EXPECT_EQ(storedValue(path(".passcode"), "pin").compare(0, 3, "$y$"), 0);

    EXPECT_TRUE(matchPasscode("7351").returnValue);
    EXPECT_FALSE(matchPasscode("7352").returnValue);
}

// An owner whose legacy hash was stored empty still gets in, and the move to
// version 2 ends the weakness.
TEST_F(AuthTest, LegacyEmptyHashOwnerStillGetsIn)
{
    std::vector<std::string> codes = nulHashCodes(2);
    ASSERT_EQ(codes.size(), 2u);
    writeLegacyPasscode(dir, "password", codes[0]);
    start();
    boot();

    EXPECT_TRUE(matchPasscode(codes[0]).returnValue);
    EXPECT_EQ(storedVersion(path(".passcode")), 2);
    EXPECT_FALSE(matchPasscode(codes[1]).returnValue);
}

TEST_F(AuthTest, WeakPinsAndPasswordsAreRefused)
{
    start();
    boot();
    struct { const char* mode; const char* code; int error; } cases[] = {
        { "pin", "0000", Security::FailureWeakPasswordRepeat },
        { "pin", "1234", Security::FailureWeakPasswordSequence },
        { "pin", "9876", Security::FailureWeakPasswordSequence },
        { "pin", "5551", Security::FailureWeakPasswordRepeat },
        { "pin", "123", Security::FailureMinLength },
        { "pin", "12a4", Security::FailureInvalidPin },
        { "pin", "", Security::FailureEmptyPasscode },
        { "password", "aaaa", Security::FailureWeakPasswordRepeat },
        { "password", "abcd", Security::FailureWeakPasswordSequence },
        { "password", "ab", Security::FailureMinLength },
    };
    for (const auto& c : cases) {
        Reply r = setPasscode(c.mode, c.code);
        EXPECT_FALSE(r.returnValue) << c.mode << " " << c.code;
        EXPECT_EQ(r.errorCode, c.error) << c.mode << " " << c.code;
    }
    EXPECT_EQ(Security::instance()->getLockMode(), "none");

    EXPECT_TRUE(setPasscode("pin", "7351").returnValue);
    EXPECT_TRUE(setPasscode("pin", "0482").returnValue);
    EXPECT_TRUE(setPasscode("password", "tr0ub4dor").returnValue);
    // A pattern is the dots visited; it has no "sequence" to refuse.
    EXPECT_TRUE(setPasscode("pattern", "0-1-2-5-8").returnValue);
}

TEST_F(AuthTest, UnknownLockModeIsRefused)
{
    start();
    boot();
    Reply r = setPasscode("bogus", "7351");
    EXPECT_FALSE(r.returnValue);
    EXPECT_EQ(r.errorCode, Security::FailureInvalidLockMode);
    EXPECT_EQ(::access(path(".passcode").c_str(), F_OK), -1);
}

TEST_F(AuthTest, NoneRemovesThePasscode)
{
    start();
    boot();
    ASSERT_TRUE(setPasscode("pin", "7351").returnValue);
    ASSERT_TRUE(setPasscode("none", "").returnValue);
    EXPECT_EQ(::access(path(".passcode").c_str(), F_OK), -1);
    EXPECT_EQ(Security::instance()->getLockMode(), "none");
    // With no passcode there is nothing to match.
    EXPECT_FALSE(matchPasscode("7351").returnValue);
}

TEST_F(AuthTest, UnwritableDirectoryIsAnError)
{
    start();
    boot();
    ASSERT_TRUE(setPasscode("pin", "7351").returnValue);

    ASSERT_EQ(::chmod(dir.c_str(), 0500), 0);
    Reply set = setPasscode("pin", "2468");
    Reply none = setPasscode("none", "");
    ASSERT_EQ(::chmod(dir.c_str(), 0700), 0);

    EXPECT_FALSE(set.returnValue);
    EXPECT_EQ(set.errorCode, Security::FailureSave);
    EXPECT_FALSE(none.returnValue);
    EXPECT_EQ(none.errorCode, Security::FailureSave);
    EXPECT_EQ(Security::instance()->getLockMode(), "pin");
    EXPECT_TRUE(matchPasscode("7351").returnValue);
}

// A short write must not replace the passcode: at the next start a file
// that does not parse is deleted, and the device would be unlocked.
TEST_F(AuthTest, ShortWriteKeepsTheOldPasscode)
{
    start();
    boot();
    ASSERT_TRUE(setPasscode("pin", "7351").returnValue);
    const std::string before = readFile(path(".passcode"));

    struct rlimit old, small;
    ASSERT_EQ(getrlimit(RLIMIT_FSIZE, &old), 0);
    small.rlim_cur = 8;
    small.rlim_max = old.rlim_max;
    signal(SIGXFSZ, SIG_IGN);
    ASSERT_EQ(setrlimit(RLIMIT_FSIZE, &small), 0);
    Reply r = setPasscode("pin", "2468");
    ASSERT_EQ(setrlimit(RLIMIT_FSIZE, &old), 0);

    EXPECT_FALSE(r.returnValue);
    EXPECT_EQ(r.errorCode, Security::FailureSave);
    EXPECT_EQ(readFile(path(".passcode")), before);
    EXPECT_EQ(::access(path(".passcode.tmp").c_str(), F_OK), -1);

    restart();
    boot();
    EXPECT_EQ(Security::instance()->getLockMode(), "pin");
    EXPECT_TRUE(matchPasscode("7351").returnValue);
}

// A temporary file left behind (or a link put there) is not written through.
TEST_F(AuthTest, StaleTemporaryFileIsNotFollowed)
{
    const std::string victim = path("victim");
    { FILE* f = fopen(victim.c_str(), "w"); ASSERT_NE(f, nullptr); fputs("keep", f); fclose(f); }
    ASSERT_EQ(::symlink(victim.c_str(), path(".passcode.tmp").c_str()), 0);

    start();
    boot();
    ASSERT_TRUE(setPasscode("pin", "7351").returnValue);
    EXPECT_EQ(readFile(victim), "keep");

    struct stat st;
    ASSERT_EQ(::lstat(path(".passcode").c_str(), &st), 0);
    EXPECT_TRUE(S_ISREG(st.st_mode));
    EXPECT_EQ(st.st_mode & 0777, 0600u);
}
