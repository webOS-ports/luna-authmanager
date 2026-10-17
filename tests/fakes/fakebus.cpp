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

#include "fakebus.h"

#include <glib.h>

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <deque>
#include <map>
#include <memory>

struct LSHandle {
    std::string name;
};

struct LSMessage {
    std::string category;
    std::string method;
    std::string payload;
    std::string sender;
    std::string appId;
    LSMessageToken responseToken = LSMESSAGE_TOKEN_INVALID;
    bool subscription = false;
    bool subscribed = false;
    std::vector<std::string>* replies = nullptr;
};

namespace {

struct Category {
    std::map<std::string, LSMethodFunction> methods;
    std::vector<std::string> signals;
    void* data = nullptr;
};

struct Match {
    LSHandle* sh;
    std::string category;
    std::string method;
    LSFilterFunc callback;
    void* ctx;
};

struct Watch {
    LSHandle* sh;
    std::string service;
    LSServerStatusFunc func;
    void* ctx;
};

struct Subscription {
    LSHandle* sh;
    std::string key;
    LSMessage* message;
};

struct State {
    std::deque<std::unique_ptr<LSHandle>> handles;
    std::deque<std::unique_ptr<LSMessage>> messages;
    std::map<std::string, std::map<std::string, Category>> categories;   // service -> category
    std::vector<Match> matches;
    std::vector<Watch> watches;
    std::vector<Subscription> subscriptions;
    std::map<LSHandle*, std::pair<LSFilterFunc, void*>> cancelFunctions;

    std::vector<fakebus::Call> calls;
    std::vector<fakebus::Signal> signals;
    std::vector<fakebus::Post> posts;
    std::vector<LSMessageToken> cancelled;
    LSMessageToken nextToken = 1;
    bool failSubscriptionAdd = false;
};

State& state()
{
    static State* s = new State;   // never destroyed: callbacks may run during exit
    return *s;
}

LSMessage* newMessage()
{
    state().messages.push_back(std::make_unique<LSMessage>());
    return state().messages.back().get();
}

void setError(LSError* lserror, const char* what)
{
    if (!lserror)
        return;
    lserror->error_code = -1;
    lserror->message = strdup(what);
    lserror->file = __FILE__;
    lserror->line = __LINE__;
    lserror->func = "fakebus";
    lserror->magic = 1;
}

// "luna://service/category/method" (or palm://) split into its parts. The
// method is the last path element, the category everything between.
bool splitUri(const std::string& uri, std::string& service, std::string& category,
              std::string& method)
{
    size_t scheme = uri.find("://");
    if (scheme == std::string::npos)
        return false;
    std::string rest = uri.substr(scheme + 3);
    size_t slash = rest.find('/');
    if (slash == std::string::npos)
        return false;
    service = rest.substr(0, slash);
    std::string path = rest.substr(slash);
    size_t last = path.rfind('/');
    method = path.substr(last + 1);
    category = last == 0 ? "/" : path.substr(0, last);
    return true;
}

// The hub's signal/addmatch payload: {"category": ..., "method": ...}.
void addMatch(LSHandle* sh, const char* payload, LSFilterFunc callback, void* ctx)
{
    gchar* category = nullptr;
    gchar* method = nullptr;
    GRegex* re = g_regex_new("\"category\"\\s*:\\s*\"([^\"]*)\"", (GRegexCompileFlags)0,
                             (GRegexMatchFlags)0, nullptr);
    GMatchInfo* mi = nullptr;
    if (g_regex_match(re, payload, (GRegexMatchFlags)0, &mi))
        category = g_match_info_fetch(mi, 1);
    g_match_info_free(mi);
    g_regex_unref(re);
    re = g_regex_new("\"method\"\\s*:\\s*\"([^\"]*)\"", (GRegexCompileFlags)0,
                     (GRegexMatchFlags)0, nullptr);
    mi = nullptr;
    if (g_regex_match(re, payload, (GRegexMatchFlags)0, &mi))
        method = g_match_info_fetch(mi, 1);
    g_match_info_free(mi);
    g_regex_unref(re);

    state().matches.push_back({sh, category ? category : "", method ? method : "", callback, ctx});
    g_free(category);
    g_free(method);
}

bool isAddMatch(const std::string& uri)
{
    return uri.find("/signal/addmatch") != std::string::npos;
}

bool doCall(LSHandle* sh, const char* uri, const char* payload, LSFilterFunc callback,
            void* ctx, LSMessageToken* ret_token, LSError* lserror, bool oneReply)
{
    if (!sh || !uri || !payload) {
        setError(lserror, "invalid parameters");
        return false;
    }
    LSMessageToken token = state().nextToken++;
    state().calls.push_back({uri, payload, callback, ctx, token, oneReply});
    if (isAddMatch(uri) && callback)
        addMatch(sh, payload, callback, ctx);
    if (ret_token)
        *ret_token = token;
    return true;
}

} // namespace

namespace fakebus {

const std::vector<Call>& calls() { return state().calls; }
const std::vector<Signal>& signals() { return state().signals; }
const std::vector<Post>& posts() { return state().posts; }
std::vector<LSMessageToken> cancelled() { return state().cancelled; }

std::vector<Call> callsTo(const std::string& prefix)
{
    std::vector<Call> out;
    for (const auto& c : state().calls)
        if (c.uri.compare(0, prefix.size(), prefix) == 0)
            out.push_back(c);
    return out;
}

std::vector<Signal> signalsTo(const std::string& prefix)
{
    std::vector<Signal> out;
    for (const auto& s : state().signals)
        if (s.uri.compare(0, prefix.size(), prefix) == 0)
            out.push_back(s);
    return out;
}

void clearRecords()
{
    state().calls.clear();
    state().signals.clear();
    state().posts.clear();
    state().cancelled.clear();
}

bool reply(LSMessageToken token, const std::string& payload)
{
    for (const auto& c : state().calls) {
        if (c.token != token)
            continue;
        if (!c.callback)
            return false;
        LSMessage* m = newMessage();
        m->payload = payload;
        m->responseToken = token;
        std::string service;
        splitUri(c.uri, service, m->category, m->method);
        m->sender = service;
        Call copy = c;   // the callback may make calls, growing the vector
        LSHandle* sh = state().handles.empty() ? nullptr : state().handles.front().get();
        copy.callback(sh, m, copy.ctx);
        return true;
    }
    return false;
}

int emitSignal(const std::string& category, const std::string& method,
               const std::string& payload)
{
    int n = 0;
    std::vector<Match> matches = state().matches;   // callbacks may add more
    for (const auto& match : matches) {
        if (match.category != category)
            continue;
        if (!match.method.empty() && match.method != method)
            continue;
        LSMessage* m = newMessage();
        m->category = category;
        m->method = method;
        m->payload = payload;
        m->sender = "com.webos.service.battery";
        match.callback(match.sh, m, match.ctx);
        n++;
    }
    return n;
}

int setServiceUp(const std::string& service, bool up)
{
    int n = 0;
    std::vector<Watch> watches = state().watches;
    for (const auto& w : watches) {
        if (w.service != service)
            continue;
        w.func(w.sh, service.c_str(), up, w.ctx);
        n++;
    }
    return n;
}

MethodResult callMethod(const std::string& service, const std::string& category,
                        const std::string& method, const std::string& payload,
                        const std::string& sender, bool subscribe)
{
    MethodResult r{false, false, {}, false};
    auto s = state().categories.find(service);
    if (s == state().categories.end())
        return r;
    auto c = s->second.find(category);
    if (c == s->second.end())
        return r;
    auto m = c->second.methods.find(method);
    if (m == c->second.methods.end())
        return r;

    LSHandle* sh = nullptr;
    for (auto& h : state().handles)
        if (h->name == service)
            sh = h.get();

    LSMessage* msg = newMessage();
    msg->category = category;
    msg->method = method;
    msg->payload = payload;
    msg->sender = sender;
    msg->appId = sender;
    msg->subscription = subscribe;
    msg->replies = &r.replies;

    r.found = true;
    r.handled = m->second(sh, msg, c->second.data);
    r.subscribed = msg->subscribed;
    msg->replies = nullptr;   // r goes out of scope; later replies are recorded only as posts
    return r;
}

int dropSubscriber(const std::string& sender)
{
    int n = 0;
    std::vector<Subscription> keep;
    std::vector<Subscription> gone;
    for (const auto& s : state().subscriptions)
        (s.message->sender == sender ? gone : keep).push_back(s);
    state().subscriptions = keep;
    // ls2 keeps one subscription per message, however many keys it was added
    // under, and calls the cancel function once for it (subscription.c
    // _CatalogRemoveToken).
    std::vector<LSMessage*> seen;
    for (const auto& s : gone) {
        if (std::find(seen.begin(), seen.end(), s.message) != seen.end())
            continue;
        seen.push_back(s.message);
        auto f = state().cancelFunctions.find(s.sh);
        if (f != state().cancelFunctions.end() && f->second.first)
            f->second.first(s.sh, s.message, f->second.second);
        n++;
    }
    return n;
}

void failNextSubscriptionAdd()
{
    state().failSubscriptionAdd = true;
}

int subscriberCount(const std::string& key)
{
    int n = 0;
    for (const auto& s : state().subscriptions)
        if (s.key == key)
            n++;
    return n;
}

std::vector<std::string> registeredServices()
{
    std::vector<std::string> out;
    for (const auto& h : state().handles)
        out.push_back(h->name);
    return out;
}

std::vector<std::string> declaredSignals(const std::string& service, const std::string& category)
{
    auto s = state().categories.find(service);
    if (s == state().categories.end())
        return {};
    auto c = s->second.find(category);
    if (c == s->second.end())
        return {};
    return c->second.signals;
}

void reset()
{
    // Handles stay: a singleton may keep its handle across tests. Messages
    // stay too: a callback may still hold one.
    State& s = state();
    s.categories.clear();
    s.matches.clear();
    s.watches.clear();
    s.subscriptions.clear();
    s.cancelFunctions.clear();
    s.failSubscriptionAdd = false;
    clearRecords();
}

} // namespace fakebus

/* ---- the luna-service2 API ---------------------------------------------- */

extern "C" {

bool LSErrorInit(LSError* error)
{
    if (!error)
        return false;
    memset(error, 0, sizeof(*error));
    return true;
}

void LSErrorFree(LSError* error)
{
    if (!error)
        return;
    free(error->message);
    LSErrorInit(error);
}

bool LSErrorIsSet(LSError* lserror)
{
    return lserror && lserror->error_code != 0;
}

void LSErrorPrint(LSError* lserror, FILE* out)
{
    if (lserror && lserror->message && out)
        fprintf(out, "LSError: %s\n", lserror->message);
}

bool LSRegister(const char* name, LSHandle** sh, LSError* lserror)
{
    if (!sh) {
        setError(lserror, "no handle");
        return false;
    }
    state().handles.push_back(std::make_unique<LSHandle>());
    state().handles.back()->name = name ? name : "";
    *sh = state().handles.back().get();
    return true;
}

bool LSUnregister(LSHandle* service, LSError* lserror)
{
    (void)service;
    (void)lserror;
    return true;
}

bool LSGmainAttach(LSHandle* sh, GMainLoop* mainLoop, LSError* lserror)
{
    (void)sh;
    (void)mainLoop;
    (void)lserror;
    return true;
}

bool LSRegisterCategory(LSHandle* sh, const char* category, LSMethod* methods, LSSignal* langis,
                        LSProperty* properties, LSError* lserror)
{
    (void)properties;
    if (!sh || !category) {
        setError(lserror, "invalid parameters");
        return false;
    }
    Category& c = state().categories[sh->name][category];
    for (LSMethod* m = methods; m && m->name; m++)
        c.methods[m->name] = m->function;
    for (LSSignal* s = langis; s && s->name; s++)
        c.signals.push_back(s->name);
    return true;
}

bool LSCategorySetData(LSHandle* sh, const char* category, void* user_data, LSError* lserror)
{
    if (!sh || !category) {
        setError(lserror, "invalid parameters");
        return false;
    }
    state().categories[sh->name][category].data = user_data;
    return true;
}

bool LSCall(LSHandle* sh, const char* uri, const char* payload, LSFilterFunc callback,
            void* user_data, LSMessageToken* ret_token, LSError* lserror)
{
    return doCall(sh, uri, payload, callback, user_data, ret_token, lserror, false);
}

bool LSCallOneReply(LSHandle* sh, const char* uri, const char* payload, LSFilterFunc callback,
                    void* ctx, LSMessageToken* ret_token, LSError* lserror)
{
    return doCall(sh, uri, payload, callback, ctx, ret_token, lserror, true);
}

bool LSCallCancel(LSHandle* sh, LSMessageToken token, LSError* lserror)
{
    (void)sh;
    (void)lserror;
    state().cancelled.push_back(token);
    return true;
}

bool LSSignalSend(LSHandle* sh, const char* uri, const char* payload, LSError* lserror)
{
    if (!sh || !uri || !payload) {
        setError(lserror, "invalid parameters");
        return false;
    }
    state().signals.push_back({uri, payload});
    return true;
}

bool LSRegisterServerStatusEx(LSHandle* sh, const char* serviceName, LSServerStatusFunc func,
                              void* ctxt, void** cookie, LSError* lserror)
{
    if (!sh || !serviceName || !func) {
        setError(lserror, "invalid parameters");
        return false;
    }
    state().watches.push_back({sh, serviceName, func, ctxt});
    if (cookie)
        *cookie = nullptr;
    return true;
}

const char* LSMessageGetPayload(LSMessage* message)
{
    return message ? message->payload.c_str() : nullptr;
}

const char* LSMessageGetCategory(LSMessage* message)
{
    return message ? message->category.c_str() : nullptr;
}

const char* LSMessageGetMethod(LSMessage* message)
{
    return message ? message->method.c_str() : nullptr;
}

const char* LSMessageGetSender(LSMessage* message)
{
    return message ? message->sender.c_str() : nullptr;
}

const char* LSMessageGetSenderServiceName(LSMessage* message)
{
    return message ? message->sender.c_str() : nullptr;
}

const char* LSMessageGetApplicationID(LSMessage* message)
{
    return message && !message->appId.empty() ? message->appId.c_str() : nullptr;
}

LSMessageToken LSMessageGetResponseToken(LSMessage* reply)
{
    return reply ? reply->responseToken : LSMESSAGE_TOKEN_INVALID;
}

bool LSMessageIsSubscription(LSMessage* lsmgs)
{
    return lsmgs && lsmgs->subscription;
}

bool LSMessageReply(LSHandle* sh, LSMessage* lsmsg, const char* replyPayload, LSError* lserror)
{
    (void)sh;
    if (!lsmsg || !replyPayload) {
        setError(lserror, "invalid parameters");
        return false;
    }
    if (lsmsg->replies)
        lsmsg->replies->push_back(replyPayload);
    else
        state().posts.push_back({lsmsg->category, lsmsg->method, replyPayload});
    return true;
}

bool LSSubscriptionAdd(LSHandle* sh, const char* key, LSMessage* message, LSError* lserror)
{
    if (!sh || !key || !message) {
        setError(lserror, "invalid parameters");
        return false;
    }
    if (state().failSubscriptionAdd) {
        state().failSubscriptionAdd = false;
        setError(lserror, "subscription refused");
        return false;
    }
    message->subscribed = true;
    state().subscriptions.push_back({sh, key, message});
    return true;
}

bool LSSubscriptionProcess(LSHandle* sh, LSMessage* message, bool* subscribed, LSError* lserror)
{
    if (!message) {
        setError(lserror, "invalid parameters");
        return false;
    }
    bool want = message->subscription;
    if (want) {
        std::string key = message->category;
        if (key.empty() || key.back() != '/')
            key += '/';
        key += message->method;
        LSSubscriptionAdd(sh, key.c_str(), message, lserror);
    }
    if (subscribed)
        *subscribed = want;
    return true;
}

bool LSSubscriptionReply(LSHandle* sh, const char* key, const char* payload, LSError* lserror)
{
    (void)sh;
    if (!key || !payload) {
        setError(lserror, "invalid parameters");
        return false;
    }
    state().posts.push_back({key, "", payload});
    return true;
}

bool LSSubscriptionPost(LSHandle* sh, const char* category, const char* method,
                        const char* payload, LSError* lserror)
{
    (void)sh;
    if (!category || !method || !payload) {
        setError(lserror, "invalid parameters");
        return false;
    }
    state().posts.push_back({category, method, payload});
    return true;
}

bool LSSubscriptionSetCancelFunction(LSHandle* sh, LSFilterFunc cancelFunction, void* ctx,
                                     LSError* lserror)
{
    (void)lserror;
    state().cancelFunctions[sh] = {cancelFunction, ctx};
    return true;
}

} // extern "C"
