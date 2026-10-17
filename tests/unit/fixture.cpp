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

#include "fixture.h"

#include <QCryptographicHash>

#include <ftw.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <fstream>
#include <sstream>
#include <vector>

const char* const kNoDevicePolicy = "{\"returnValue\":true,\"results\":[]}";
const char* const kNoPolicies = "{\"returnValue\":true,\"results\":[]}";
const char* const kDeleted = "{\"returnValue\":true,\"count\":0}";

static GMainLoop* s_loop = nullptr;

Reply parseReply(const fakebus::MethodResult& r)
{
    Reply out;
    if (r.replies.empty())
        return out;
    out.raw = r.replies.back();
    json_object* o = json_tokener_parse(out.raw.c_str());
    if (!o)
        return out;
    out.ok = true;
    json_object* v = nullptr;
    if (json_object_object_get_ex(o, "returnValue", &v))
        out.returnValue = json_object_get_boolean(v);
    if (json_object_object_get_ex(o, "lockedOut", &v))
        out.lockedOut = json_object_get_boolean(v);
    if (json_object_object_get_ex(o, "retriesLeft", &v))
        out.retriesLeft = json_object_get_int(v);
    if (json_object_object_get_ex(o, "errorCode", &v))
        out.errorCode = json_object_get_int(v);
    if (json_object_object_get_ex(o, "lockoutSeconds", &v))
        out.lockoutSeconds = json_object_get_int(v);
    json_object_put(o);
    return out;
}

Reply callAuth(const char* method, const std::string& payload, const char* service)
{
    return parseReply(fakebus::callMethod(service, "/", method, payload));
}

Reply setPasscode(const std::string& mode, const std::string& code)
{
    return callAuth("setDevicePasscode", "{\"lockMode\":\"" + mode + "\",\"passCode\":\"" + code + "\"}");
}

Reply matchPasscode(const std::string& code)
{
    return callAuth("matchDevicePasscode", "{\"passCode\":\"" + code + "\"}");
}

bool replyLast(const std::string& uri, const std::string& payload)
{
    auto c = fakebus::callsTo(uri);
    if (c.empty())
        return false;
    return fakebus::reply(c.back().token, payload);
}

std::string readFile(const std::string& path)
{
    std::ifstream f(path);
    std::stringstream ss;
    ss << f.rdbuf();
    return ss.str();
}

std::string legacyHash(const std::string& code)
{
    QByteArray h = QCryptographicHash::hash(QByteArray(code.c_str()), QCryptographicHash::Sha1);
    return std::string(h.constData());
}

void writeLegacyPasscode(const std::string& dir, const std::string& mode, const std::string& code)
{
    json_object* o = json_object_new_object();
    json_object_object_add(o, mode.c_str(), json_object_new_string(legacyHash(code).c_str()));
    ASSERT_EQ(json_object_to_file((dir + "/.passcode").c_str(), o), 0);
    json_object_put(o);
}

static int removeEntry(const char* p, const struct stat*, int, struct FTW*)
{
    return ::remove(p);
}

void AuthTest::SetUp()
{
    if (!s_loop)
        s_loop = g_main_loop_new(nullptr, FALSE);

    char cwd[4096];
    ASSERT_NE(getcwd(cwd, sizeof cwd), nullptr);
    std::string tmpl = std::string(cwd) + "/authtest-XXXXXX";
    std::vector<char> buf(tmpl.begin(), tmpl.end());
    buf.push_back('\0');
    ASSERT_NE(mkdtemp(buf.data()), nullptr);
    dir = buf.data();
    fakeplatform::setDataDir(dir);
    fakebus::reset();
}

void AuthTest::TearDown()
{
    stop();
    ::chmod(dir.c_str(), 0700);
    nftw(dir.c_str(), removeEntry, 8, FTW_DEPTH | FTW_PHYS);
}

void AuthTest::start()
{
    fakebus::reset();
    ASSERT_TRUE(AuthService::instance()->init(s_loop));
    (void) Security::instance();
    ASSERT_TRUE(EASPolicyManager::instance()->load());
    started = true;
}

void AuthTest::boot(const char* devicePolicy, const char* policies)
{
    ASSERT_TRUE(replyLast("palm://com.palm.db/del", kDeleted));
    ASSERT_TRUE(replyLast("palm://com.palm.db/find", devicePolicy));
    ASSERT_TRUE(replyLast("palm://com.palm.db/find", policies));
}

void AuthTest::stop()
{
    if (!started)
        return;
    delete Security::instance();
    delete EASPolicyManager::instance();
    started = false;
}

void AuthTest::restart()
{
    stop();
    start();
}
