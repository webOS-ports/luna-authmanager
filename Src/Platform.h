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

#ifndef PLATFORM_H
#define PLATFORM_H

#include <stddef.h>
#include <stdint.h>

#include <string>

/*
 * What the daemon takes from the system rather than from the bus: where its
 * files live, what time it is, which boot this is, and random bytes. Platform.cpp has the real ones; the tests
 * link their own, so they can run in a scratch directory and move the clock.
 */

// The directory holding .passcode ("/var/luna/data" on the device).
const char* authDataDir();

// The directory holding the lockout state ("/var/lib/authmanager" on the
// device). Created 0700 when missing.
const char* authStateDir();

// CLOCK_MONOTONIC in milliseconds.
uint64_t monotonicMs();

// CLOCK_REALTIME in milliseconds since the epoch. Only for carrying a
// lockout across a reboot, where the monotonic clock starts again.
uint64_t realtimeMs();

// The kernel's id for this boot (/proc/sys/kernel/random/boot_id), or an
// empty string if it cannot be read.
std::string bootId();

// len bytes from the kernel's random source. False if it fails.
bool randomBytes(void* buf, size_t len);

#endif // PLATFORM_H
