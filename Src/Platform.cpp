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

#include <errno.h>
#include <fcntl.h>
#include <sys/random.h>
#include <time.h>
#include <unistd.h>

const char* authDataDir()
{
    return "/var/luna/data";
}

const char* authStateDir()
{
    return "/var/lib/authmanager";
}

uint64_t monotonicMs()
{
    struct timespec t;
    ::clock_gettime(CLOCK_MONOTONIC, &t);
    // In 64 bits: on armv7 tv_sec is a 32-bit long, and tv_sec * 1000
    // overflowed it after 24.8 days of uptime.
    return (uint64_t) t.tv_sec * 1000 + (uint64_t) t.tv_nsec / 1000000;
}

uint64_t realtimeMs()
{
    struct timespec t;
    ::clock_gettime(CLOCK_REALTIME, &t);
    if (t.tv_sec < 0)
        return 0;
    return (uint64_t) t.tv_sec * 1000 + (uint64_t) t.tv_nsec / 1000000;
}

std::string bootId()
{
    // 36 characters and a newline; read with read(2), so nothing can leak
    // or be left half-read if the string below throws.
    char buf[64];
    ssize_t n = -1;
    int fd = ::open("/proc/sys/kernel/random/boot_id", O_RDONLY | O_CLOEXEC);
    if (fd != -1) {
        do {
            n = ::read(fd, buf, sizeof(buf) - 1);
        } while (n < 0 && errno == EINTR);
        ::close(fd);
    }
    if (n <= 0)
        return std::string();

    size_t len = 0;
    while (len < (size_t) n && buf[len] != '\n')
        ++len;
    return std::string(buf, len);
}

bool randomBytes(void* buf, size_t len)
{
    unsigned char* p = static_cast<unsigned char*>(buf);
    while (len > 0) {
        ssize_t n = ::getrandom(p, len, 0);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            return false;
        }
        p += n;
        len -= (size_t) n;
    }
    return true;
}
