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

#include <stdint.h>

/*
 * What the daemon takes from the system rather than from the bus: where its
 * files live and what time it is. Platform.cpp has the real ones; the tests
 * link their own, so they can run in a scratch directory and move the clock.
 */

// The directory holding .passcode ("/var/luna/data" on the device).
const char* authDataDir();

// CLOCK_MONOTONIC in milliseconds.
uint64_t monotonicMs();

#endif // PLATFORM_H
