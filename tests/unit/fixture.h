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

#ifndef AUTH_TEST_FIXTURE_H
#define AUTH_TEST_FIXTURE_H

#include "AuthService.h"
#include "EASPolicyManager.h"
#include "Security.h"
#include "fakebus.h"
#include "fakeplatform.h"

#include <glib.h>
#include <gtest/gtest.h>
#include <json.h>

#include <string>

// A matchDevicePasscode / setDevicePasscode / ... reply, parsed.
struct Reply {
    bool ok = false;            // a reply came, and it is JSON
    bool returnValue = false;
    bool lockedOut = false;
    int retriesLeft = -1;
    int errorCode = 0;
    int lockoutSeconds = -1;
    std::string raw;
};

Reply parseReply(const fakebus::MethodResult& r);
Reply callAuth(const char* method, const std::string& payload,
               const char* service = "com.palm.systemmanager");
Reply setPasscode(const std::string& mode, const std::string& code);
Reply matchPasscode(const std::string& code);

// Answer the last call to uri (as db8 would). False if there was none.
bool replyLast(const std::string& uri, const std::string& payload);

std::string readFile(const std::string& path);

// The raw SHA-1 luna-sysmgr stored, cut at its first NUL as it was.
std::string legacyHash(const std::string& code);

// Write a passcode file the way luna-sysmgr did.
void writeLegacyPasscode(const std::string& dir, const std::string& mode, const std::string& code);

extern const char* const kNoDevicePolicy;
extern const char* const kNoPolicies;
extern const char* const kDeleted;

// Every test gets its own data directory and a clean bus; start() brings up
// the daemon's singletons as Src/Main.cpp does, boot() plays db8's side of
// the start-up.
class AuthTest : public ::testing::Test {
protected:
    void SetUp() override;
    void TearDown() override;

    void start();
    void boot(const char* devicePolicy = kNoDevicePolicy, const char* policies = kNoPolicies);
    void stop();
    void restart();

    std::string path(const char* name) const { return dir + "/" + name; }

    std::string dir;
    bool started = false;
};

#endif
