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

// The bus methods against bad requests, and the ACG files that decide who
// may call them.

#include "fixture.h"

#include <set>

TEST_F(AuthTest, MalformedSetRequestsAreErrors)
{
    start();
    boot();
    const char* payloads[] = {
        "{}", "{\"passCode\":\"7351\"}", "not json", "{\"lockMode\":null}",
        "{\"lockMode\":5,\"passCode\":\"7351\"}", "{\"lockMode\":\"pin\",\"passCode\":7351}",
        "{\"lockMode\":\"pin\",\"passCode\":{}}",
    };
    for (const char* p : payloads) {
        Reply r = callAuth("setDevicePasscode", p);
        EXPECT_TRUE(r.ok) << p;
        EXPECT_FALSE(r.returnValue) << p;
        EXPECT_EQ(r.errorCode, Security::FailureBadRequest) << p;
    }
    EXPECT_EQ(Security::instance()->getLockMode(), "none");
}

TEST_F(AuthTest, MatchNeedsAStringPasscode)
{
    start();
    boot();
    ASSERT_TRUE(setPasscode("pin", "7351").returnValue);
    EXPECT_FALSE(callAuth("matchDevicePasscode", "{\"passCode\":7351}").returnValue);
    EXPECT_FALSE(callAuth("matchDevicePasscode", "{}").returnValue);
    // Not a guess: the count did not move.
    EXPECT_EQ(matchPasscode("0482").retriesLeft, 4);
}

TEST_F(AuthTest, BothNamesServeTheMethods)
{
    start();
    boot();
    ASSERT_TRUE(callAuth("setDevicePasscode", "{\"lockMode\":\"pin\",\"passCode\":\"7351\"}",
                         "com.webos.service.auth").returnValue);
    EXPECT_TRUE(callAuth("matchDevicePasscode", "{\"passCode\":\"7351\"}",
                         "com.webos.service.auth").returnValue);
    EXPECT_TRUE(matchPasscode("7351").returnValue);
}

TEST_F(AuthTest, HostilePayloadsDoNotCrash)
{
    start();
    boot();
    const char* payloads[] = {
        "", "[]", "null", "1", "\"x\"", "{\"lockMode\":null}", "{\"lockMode\":5,\"passCode\":[]}",
        "{\"lockMode\":\"pin\",\"passCode\":null}", "{\"lockMode\":\"pin\",\"passCode\":{}}",
        "{\"passCode\":null}", "{\"passCode\":7}", "{\"subscribe\":\"yes\"}",
        "{\"lockMode\":\"pin\",\"passCode\":\"\\u0000\"}",
    };
    for (const char* p : payloads)
        for (const char* m : { "setDevicePasscode", "matchDevicePasscode", "getDeviceLockMode", "getSecurityPolicy" })
            (void) callAuth(m, p);
}

namespace {

json_object* sysbusFile(const char* name)
{
    return json_object_from_file((std::string(AUTH_SOURCE_DIR "/files/sysbus/") + name).c_str());
}

std::set<std::string> groupMethods(json_object* api, const char* group)
{
    std::set<std::string> out;
    json_object* a = nullptr;
    if (!json_object_object_get_ex(api, group, &a))
        return out;
    for (size_t i = 0; i < json_object_array_length(a); ++i)
        out.insert(json_object_get_string(json_object_array_get_idx(a, i)));
    return out;
}

} // namespace

// Setting or matching the passcode is for the lock screen and Settings
// only, not for whatever app holds luna-sysmgr.operation. auth.verify
// matches, and only that: an app that asks for the passcode to let its
// user in has no business setting or clearing it.
TEST(Acg, PasscodeMethodsHaveAGroupOfTheirOwn)
{
    json_object* api = sysbusFile("luna-authmanager.api.json");
    ASSERT_NE(api, nullptr);

    std::set<std::string> passcode = groupMethods(api, "auth.passcode");
    for (const char* name : { "com.palm.systemmanager", "com.webos.service.auth" })
        for (const char* m : { "setDevicePasscode", "matchDevicePasscode" })
            EXPECT_EQ(passcode.count(std::string(name) + "/" + m), 1u) << name << "/" << m;

    std::set<std::string> verify = groupMethods(api, "auth.verify");
    EXPECT_EQ(verify, std::set<std::string>{ "com.webos.service.auth/matchDevicePasscode" });

    json_object_object_foreach(api, group, methods) {
        if (std::string(group) == "auth.passcode" || std::string(group) == "auth.verify")
            continue;
        for (size_t i = 0; i < json_object_array_length(methods); ++i) {
            std::string m = json_object_get_string(json_object_array_get_idx(methods, i));
            EXPECT_EQ(m.find("DevicePasscode"), std::string::npos) << group << ": " << m;
        }
    }
    json_object_put(api);

    json_object* groups = sysbusFile("luna-authmanager.groups.json");
    ASSERT_NE(groups, nullptr);
    json_object* trust = nullptr;
    ASSERT_TRUE(json_object_object_get_ex(groups, "auth.passcode", &trust));
    EXPECT_STREQ(json_object_to_json_string(trust), "[ \"oem\" ]");
    ASSERT_TRUE(json_object_object_get_ex(groups, "auth.verify", &trust));
    EXPECT_STREQ(json_object_to_json_string(trust), "[ \"oem\" ]");
    json_object_put(groups);
}

// The wipe goes out from the keymanager name; storaged lets only
// storaged.operation call erase/Wipe.
TEST(Acg, KeymanagerNameMayWipe)
{
    json_object* perm = sysbusFile("luna-authmanager.perm.json");
    ASSERT_NE(perm, nullptr);
    json_object* km = nullptr;
    ASSERT_TRUE(json_object_object_get_ex(perm, "com.palm.systemmanager-keymanager", &km));
    std::set<std::string> held;
    for (size_t i = 0; i < json_object_array_length(km); ++i)
        held.insert(json_object_get_string(json_object_array_get_idx(km, i)));
    EXPECT_EQ(held.count("storaged.operation"), 1u);
    EXPECT_EQ(held.count("keymanager-service.operation"), 1u);
    json_object_put(perm);
}
