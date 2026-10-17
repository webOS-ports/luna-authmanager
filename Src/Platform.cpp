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

#include "Platform.h"

#include <time.h>

const char* authDataDir()
{
    return "/var/luna/data";
}

uint64_t monotonicMs()
{
    struct timespec t;
    ::clock_gettime(CLOCK_MONOTONIC, &t);
    // In 64 bits: on armv7 tv_sec is a 32-bit long, and tv_sec * 1000
    // overflowed it after 24.8 days of uptime.
    return (uint64_t) t.tv_sec * 1000 + (uint64_t) t.tv_nsec / 1000000;
}
