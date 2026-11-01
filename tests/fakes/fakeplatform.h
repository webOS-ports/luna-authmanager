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

/*
 * The test side of Src/Platform.h: the data directory is the test's own
 * scratch directory, and the clocks only move when a test moves them.
 */

#ifndef FAKEPLATFORM_H
#define FAKEPLATFORM_H

#include <stdint.h>

#include <string>

namespace fakeplatform {

void setDataDir(const std::string& dir);
void setStateDir(const std::string& dir);

// Moves the monotonic and the wall clock alike, as time passing does.
void advanceMs(uint64_t ms);

// The wall clock alone: set by hand, or by a reset RTC.
void setRealtimeMs(uint64_t ms);
uint64_t realtimeNowMs();

// A reboot: a new boot id, and the monotonic clock starting again (from a
// point a test cannot mistake for the old boot's).
void reboot();
void setBootId(const std::string& id);

// Make randomBytes() fail until called with false.
void failRandom(bool fail);

} // namespace fakeplatform

#endif
