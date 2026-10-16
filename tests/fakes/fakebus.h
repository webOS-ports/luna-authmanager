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
 * An in-process luna-service2 for the tests.
 *
 * The test binary defines the LS2 functions the daemon uses, and is not
 * linked with libluna-service2, so no hub is needed. Everything sent is
 * recorded; methods, signal matches and server status watches are kept so a
 * test can play the other side of the bus.
 */

#ifndef FAKEBUS_H
#define FAKEBUS_H

#include <luna-service2/lunaservice.h>

#include <string>
#include <vector>

namespace fakebus {

struct Call {
    std::string uri;
    std::string payload;
    LSFilterFunc callback;
    void* ctx;
    LSMessageToken token;
    bool oneReply;
};

struct Signal {
    std::string uri;
    std::string payload;
};

struct Post {
    std::string category;
    std::string method;
    std::string payload;
};

// What the daemon sent, in order.
const std::vector<Call>& calls();
const std::vector<Signal>& signals();
const std::vector<Post>& posts();
std::vector<LSMessageToken> cancelled();

// Calls (or signals) whose URI starts with prefix.
std::vector<Call> callsTo(const std::string& prefix);
std::vector<Signal> signalsTo(const std::string& prefix);

void clearRecords();

// Deliver a reply to the call that got this token, as the bus would.
bool reply(LSMessageToken token, const std::string& payload);

// Deliver a signal to every signal/addmatch whose category and method match,
// as the hub would. Returns how many matches it reached.
int emitSignal(const std::string& category, const std::string& method,
               const std::string& payload);

// Tell every LSRegisterServerStatusEx watcher of this service.
int setServiceUp(const std::string& service, bool up);

struct MethodResult {
    bool found;            // a method of that name was registered
    bool handled;          // what the handler returned
    std::vector<std::string> replies;
    bool subscribed;       // LSSubscriptionAdd was called on the message
};

// Call a method the daemon registered, as a client called sender would.
MethodResult callMethod(const std::string& service, const std::string& category,
                        const std::string& method, const std::string& payload,
                        const std::string& sender = "com.example.test",
                        bool subscribe = false);

// The client called sender goes away: its subscriptions are dropped and the
// LSSubscriptionSetCancelFunction callback runs once per subscribed message,
// as in ls2. Returns how many messages.
int dropSubscriber(const std::string& sender);

// Make the next LSSubscriptionAdd fail, as ls2 does when it cannot.
void failNextSubscriptionAdd();

// Subscriptions the daemon holds under this key (LSSubscriptionAdd).
int subscriberCount(const std::string& key);

// Names the daemon registered on the bus (LSRegister).
std::vector<std::string> registeredServices();

// Signals declared in an LSRegisterCategory table.
std::vector<std::string> declaredSignals(const std::string& service,
                                         const std::string& category);

// Forget every registration, match, watch and subscription, before a test
// starts the daemon's singletons again. LSHandles survive.
void reset();

} // namespace fakebus

#endif
