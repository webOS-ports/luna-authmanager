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

#include "fakeplatform.h"

#include "Platform.h"

#include <sys/random.h>

namespace {

std::string s_dataDir = ".";
std::string s_stateDir = "./state";
// Not 0: the daemon's "locked out until" starts at 0.
uint64_t s_nowMs = 1000000;
// 2026-10-29T00:00:00Z.
uint64_t s_wallMs = 1793232000000ULL;
std::string s_bootId = "8a1c7e0e-0000-4000-8000-000000000001";
unsigned s_boots = 1;
bool s_failRandom = false;

}

namespace fakeplatform {

void setDataDir(const std::string& dir)
{
    s_dataDir = dir;
}

void setStateDir(const std::string& dir)
{
    s_stateDir = dir;
}

void advanceMs(uint64_t ms)
{
    s_nowMs += ms;
    s_wallMs += ms;
}

void setRealtimeMs(uint64_t ms)
{
    s_wallMs = ms;
}

uint64_t realtimeNowMs()
{
    return s_wallMs;
}

void reboot()
{
    ++s_boots;
    s_bootId = "8a1c7e0e-0000-4000-8000-" + std::to_string(100000000000ULL + s_boots);
    // Less than before: a monotonic deadline carried over would look far off.
    s_nowMs = 5000 + s_boots;
}

void setBootId(const std::string& id)
{
    s_bootId = id;
}

void failRandom(bool fail)
{
    s_failRandom = fail;
}

} // namespace fakeplatform

const char* authDataDir()
{
    return s_dataDir.c_str();
}

uint64_t monotonicMs()
{
    return s_nowMs;
}

const char* authStateDir()
{
    return s_stateDir.c_str();
}

uint64_t realtimeMs()
{
    return s_wallMs;
}

std::string bootId()
{
    return s_bootId;
}

bool randomBytes(void* buf, size_t len)
{
    if (s_failRandom)
        return false;
    return ::getrandom(buf, len, 0) == (ssize_t) len;
}
