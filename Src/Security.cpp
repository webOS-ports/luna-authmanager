/* @@@LICENSE
*
*      Copyright (c) 2009-2013 LG Electronics, Inc.
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

#include "Security.h"

#include "EASPolicyManager.h"
#include "AuthService.h"
#include "Platform.h"

#include <crypt.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <glib.h>
#include <json.h>

#include <QCryptographicHash>
#include <QString>

/*
 * The passcode file holds the lock mode as its one key, with the hashed
 * passcode as the value:
 *
 *   {"version": 2, "pin": "$y$j7T$<salt>$<hash>"}
 *
 * A version 2 value is a yescrypt string from crypt(3), with a fresh salt for
 * every passcode. A file without "version" is what luna-sysmgr wrote: the
 * raw SHA-1 of the passcode stored as a C string, and so cut at the first NUL
 * byte of the hash. Such a file is still matched the way it always was, and
 * is rewritten as version 2 the first time the right passcode is given.
 */
static const int s_passcodeVersion = 2;
static const char s_hashPrefix[] = "$y$";

// yescrypt's cost, as crypt_gensalt takes it. Measured on a tenderloin
// (armv7): 70 ms and 4.5 MiB a hash at 3, 145 ms at 4, 285 ms and 16.5 MiB
// at libxcrypt's default of 5, every one of them paid on each unlock. The
// lockout is what holds off guessing on the device; the cost is for a copy
// of the file. The cost is part of each stored hash, so changing it here
// leaves passcodes already set working.
static const unsigned long s_hashCost = 3;

// Lock modes that hash-and-store a passcode the same way: a PIN and a
// password always did, and a drawn pattern needs nothing more than that
// either - the nine dots visited, joined by index ("0-1-2-5-8"), is just
// another string to hash and compare, the same as a typed PIN was.
//
// "face" is here too, ahead of anything that can actually check one: no
// LuneOS device has the camera pipeline or the model that would tell a face
// from a photo of one, so nothing calls setDevicePasscode with lockMode
// "face" yet. Accepting the mode now means that service, whenever it exists,
// only has to start calling this one rather than also getting a mode added
// for it first.
static const char* const s_storedLockModes[] = { "pin", "password", "pattern", "face", 0 };

static bool isStoredLockMode(const std::string& mode)
{
    for (int i = 0; s_storedLockModes[i] != 0; ++i) {
        if (mode == s_storedLockModes[i])
            return true;
    }
    return false;
}

static std::string passcodeFile()
{
    return std::string(authDataDir()) + "/.passcode";
}

// A comparison whose time does not depend on where the strings differ.
static bool equalConstantTime(const std::string& a, const std::string& b)
{
    if (a.size() != b.size())
        return false;

    unsigned char diff = 0;
    for (size_t i = 0; i < a.size(); ++i)
        diff |= (unsigned char) (a[i] ^ b[i]);
    return diff == 0;
}

// crypt(3) of the passcode under setting: a fresh salt, or a stored hash to
// check against. Empty if crypt fails.
static std::string cryptPasscode(const std::string& passcode, const char* setting)
{
    // struct crypt_data is 32 KiB: not for the stack.
    struct crypt_data* data = static_cast<struct crypt_data*>(g_malloc0(sizeof(struct crypt_data)));
    const char* out = crypt_rn(passcode.c_str(), setting, data, sizeof(struct crypt_data));
    std::string result = (out != 0 && out[0] != '*') ? out : "";
    explicit_bzero(data, sizeof(struct crypt_data));
    g_free(data);
    return result;
}

static std::string hashPasscode(const std::string& passcode)
{
    char salt[CRYPT_GENSALT_OUTPUT_SIZE];

    // The salt's random bytes come from the kernel.
    if (!crypt_gensalt_rn(s_hashPrefix, s_hashCost, NULL, 0, salt, sizeof(salt))) {
        g_warning("%s: cannot make a salt: %s", __func__, g_strerror(errno));
        return "";
    }
    return cryptPasscode(passcode, salt);
}

static bool matchHash(const std::string& passcode, const std::string& stored)
{
    if (stored.compare(0, strlen(s_hashPrefix), s_hashPrefix) != 0)
        return false;

    std::string computed = cryptPasscode(passcode, stored.c_str());
    return !computed.empty() && equalConstantTime(computed, stored);
}

// The comparison luna-sysmgr made, exactly: both hashes cut at their first
// NUL byte. That is weak for the 1 in 256 passcodes whose hash starts with
// one, but refusing them instead would lock those owners out for good; the
// first right passcode moves the file to version 2 and ends it either way.
static bool matchLegacy(const std::string& passcode, const std::string& stored)
{
    QByteArray hashed = QCryptographicHash::hash(QString(passcode.c_str()).toUtf8(),
                                                 QCryptographicHash::Sha1);
    std::string legacy(hashed.constData());
    bool matched = equalConstantTime(legacy, stored);
    hashed.fill(0);
    legacy.replace(0, legacy.size(), legacy.size(), 0);
    return matched;
}

// The stored hash for mode, and the file's format version. False if there
// is no passcode file or it holds nothing for mode.
static bool readStoredPasscode(const std::string& mode, int& version, std::string& hash)
{
    json_object* root = json_object_from_file(passcodeFile().c_str());
    if (!root)
        return false;

    bool found = false;
    json_object* key = 0;
    if (json_object_object_get_ex(root, mode.c_str(), &key) && json_object_is_type(key, json_type_string)) {
        hash = json_object_get_string(key);
        found = true;
    }

    version = 0;
    if (json_object_object_get_ex(root, "version", &key))
        version = json_object_get_int(key);

    json_object_put(root);
    return found;
}

static bool writeAll(int fd, const char* buf, size_t len)
{
    while (len > 0) {
        ssize_t n = ::write(fd, buf, len);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            return false;
        }
        if (n == 0) {
            errno = EIO;
            return false;
        }
        buf += n;
        len -= (size_t) n;
    }
    return true;
}

static const char* failureText(int errorCode, const std::string& mode)
{
    switch (errorCode) {
        case Security::FailureEmptyPasscode: return "Passcode is empty";
        case Security::FailureMinLength: return "Passcode not minimum length";
        case Security::FailureInvalidPassword: return "Alphanumeric characters required";
        case Security::FailureAlphaNumeric: return "Alphanumeric characters required";
        case Security::FailureInvalidPin: return "Pin invalid";
        case Security::FailureWeakPasswordRepeat:
            return mode == "pin" ? "No repeating numbers (3333)" : "No repeating characters (aaaa)";
        case Security::FailureWeakPasswordSequence:
            return mode == "pin" ? "No sequential numbers (1234)" : "No sequential characters (abcd)";
        default: return "Passcode general failure";
    }
}

static int validateStrength(const QString& passcode);

// What every PIN and password has to meet, with or without an EAS policy:
// at least four characters, digits only for a PIN, and no run of repeated or
// sequential characters longer than half of it (no 0000, 1234 or 9876). An
// EAS policy can ask for more, never for less. A pattern's string is the
// dots visited, where a "sequence" means nothing; Settings has it connect at
// least four.
static int validateBaseline(const std::string& mode, const std::string& passcode)
{
    if (mode != "pin" && mode != "password")
        return Security::Success;

    if (passcode.empty())
        return Security::FailureEmptyPasscode;

    QString pass = QString::fromUtf8(passcode.c_str());
    if (pass.length() < (int) Security::s_minPasscodeLength)
        return Security::FailureMinLength;

    if (mode == "pin") {
        for (int i = 0; i < pass.length(); i++) {
            if (!pass.at(i).isDigit())
                return Security::FailureInvalidPin;
        }
    }

    return validateStrength(pass);
}

static Security* s_instance = 0;


Security* Security::instance()
{
    if (G_UNLIKELY(s_instance == 0)) {
        s_instance = new Security;
    }
    return s_instance;
}

Security::Security()
    : m_service(0)
    , m_failures(0)
    , m_lockedUntilMs(0)
{
    readLockMode();

    registerService();
}

Security::~Security()
{
    LSError lserror;
    LSErrorInit(&lserror);
    if (m_service && !LSUnregister(m_service, &lserror)) {
        g_message("%s: failed to unregister: %s", __FUNCTION__, lserror.message);
        LSErrorFree(&lserror);
    }
    s_instance = NULL;
}

void Security::registerService()
{
    LSError err;
    LSErrorInit(&err);
    if (LSRegister("com.palm.systemmanager-keymanager", &m_service, &err)) {
        if (LSGmainAttach(m_service, AuthService::instance()->mainLoop(), &err)) {

            LSCall(m_service, "palm://com.palm.bus/signal/registerServerStatus",
                   "{\"serviceName\":\"com.palm.keymanager\"}", keyManagerConnected, NULL, NULL, &err);

            // attempt to unlock the key manager
            initKeyManager();
        }
    }
    if (LSErrorIsSet(&err)) {
        // g_error() does not return: print the reason first.
        LSErrorPrint(&err, stderr);
        g_error("%s: failed to register service handle: %s", __PRETTY_FUNCTION__, err.message);
    }
}

bool Security::keyManagerConnected(LSHandle*, LSMessage* msg, void*)
{
    json_object* root = 0;
    const char* str = LSMessageGetPayload(msg);
    if (!str)
        return false;

    root = json_tokener_parse(str);
    if (!root)
        return true;

    bool connected = json_object_get_boolean(json_object_object_get(root, "connected"));
    if (connected) {
        // key manager daemon (re)started, need to unlock it again
        Security::instance()->initKeyManager();
    }

    json_object_put(root);

    return true;
}

void Security::initKeyManager()
{
    LSError err;
    LSErrorInit(&err);

    // The keymanager is unlocked with an empty password, as it has been
    // since luna-sysmgr's passcode decryption was taken out: only a hash of
    // the device passcode is kept, so there is nothing else to give it.
    json_object* payload = json_object_new_object();
    json_object_object_add(payload, "password", json_object_new_string(""));
    if (!LSCallOneReply(m_service, "palm://com.palm.keymanager/initialize",
                        json_object_to_json_string(payload), NULL, NULL, NULL, &err)) {
        g_warning("%s: failed to initialize keymanager", __PRETTY_FUNCTION__);
        LSErrorPrint(&err, stderr);
        LSErrorFree(&err);
    }

    json_object_put(payload);
}

int Security::setPasscode(const std::string& mode, const std::string& passcode, std::string& errorText)
{
    if (mode != "none" && !isStoredLockMode(mode)) {
        errorText = "Unknown lock mode";
        return FailureInvalidLockMode;
    }

    const EASPolicy * const policy = EASPolicyManager::instance()->getPolicy();

    int errorCode = validateBaseline(mode, passcode);

    // try to protect our policy
    if (errorCode == Success && policy != 0 && policy->passwordRequired())
        errorCode = validatePasscode(policy, mode, passcode);

    if (errorCode < 0) {
        errorText = failureText(errorCode, mode);
        return errorCode;
    }

    if (mode == "none") {
        if (::unlink(passcodeFile().c_str()) != 0 && errno != ENOENT) {
            g_warning("%s: cannot remove the passcode: %s", __PRETTY_FUNCTION__, g_strerror(errno));
            errorText = "Passcode save failed";
            return FailureSave;
        }
    }
    else {
        if (passcode.empty()) {
            errorText = "Passcode empty";
            return FailureEmptyPasscode;
        }

        std::string hash = hashPasscode(passcode);
        if (hash.empty() || !writePasscode(mode, hash)) {
            errorText = "Passcode save failed";
            return FailureSave;
        }

        EASPolicyManager::instance()->passwordEnforced();
    }

    m_lockMode = mode;

    // A new passcode is not guessed at yet.
    m_failures = 0;
    m_lockedUntilMs = 0;

    // inform subscribers of the new mode/policy
    AuthService::instance()->postDeviceLockMode();

    return Success;
}

bool Security::matchPasscode(const std::string& passcode, int& retriesLeft, bool& lockedOut,
                             uint32_t& lockoutSeconds)
{
    EASPolicyManager* pm = EASPolicyManager::instance();
    const EASPolicy * const policy = pm->getPolicy();
    const bool policyActive = policy != 0 && !pm->policyPending();
    const uint64_t now = monotonicMs();

    lockedOut = false;
    lockoutSeconds = 0;

    // While a lockout runs a try is refused without being checked, so the
    // answer tells nothing about whether it was right.
    if (now < m_lockedUntilMs) {
        lockedOut = true;
        lockoutSeconds = (uint32_t) ((m_lockedUntilMs - now + 999) / 1000);
        retriesLeft = 0;
        return false;
    }

    int version = 0;
    std::string stored;
    if (!readStoredPasscode(m_lockMode, version, stored)) {
        // No passcode is set: nothing to match, and no guess to count.
        retriesLeft = attemptsLeft();
        return false;
    }

    bool matched = version >= s_passcodeVersion ? matchHash(passcode, stored)
                                                : matchLegacy(passcode, stored);
    if (matched) {
        if (version < s_passcodeVersion) {
            std::string hash = hashPasscode(passcode);
            if (hash.empty() || !writePasscode(m_lockMode, hash))
                g_warning("%s: passcode left in the old format", __PRETTY_FUNCTION__);
        }

        m_failures = 0;
        m_lockedUntilMs = 0;

        // reset allowable passcode failures
        if (policyActive)
            pm->resetRetries();
        retriesLeft = attemptsLeft();
        return true;
    }

    if (m_failures < UINT32_MAX)
        m_failures++;

    if (m_failures >= s_freeAttempts) {
        uint32_t doublings = m_failures - s_freeAttempts;
        uint64_t delay = s_firstLockoutMs;
        while (doublings-- > 0 && delay < s_maxLockoutMs)
            delay *= 2;
        if (delay > s_maxLockoutMs)
            delay = s_maxLockoutMs;

        m_lockedUntilMs = now + delay;
        lockedOut = true;
        lockoutSeconds = (uint32_t) (delay / 1000);
    }

    if (policyActive && policy->validMaxRetries()) {
        retriesLeft = pm->decrementRetries();
        if (retriesLeft == 0)
            eraseDevice(); // boom
    }
    else {
        retriesLeft = attemptsLeft();
    }

    return false;
}

int Security::attemptsLeft() const
{
    if (monotonicMs() < m_lockedUntilMs)
        return 0;

    // After a lockout, one try before the next one.
    return m_failures < s_freeAttempts ? (int) (s_freeAttempts - m_failures) : 1;
}

void Security::readLockMode()
{
    const std::string file = passcodeFile();

    m_lockMode = "none";

    if (g_file_test(file.c_str(), G_FILE_TEST_EXISTS)) {

        json_object* root = json_object_from_file(file.c_str());
        if (root) {

            // setPasscode() always writes a fresh object, under whichever
            // one of these modes was chosen, so exactly one key is ever
            // present - the first one found is the right one.
            for (int i = 0; s_storedLockModes[i] != 0; ++i) {
                if (json_object_object_get_ex(root, s_storedLockModes[i], NULL)) {
                    m_lockMode = s_storedLockModes[i];
                    break;
                }
            }

            json_object_put(root);
        }

        // somehow, this is garbage so reset it
        if (m_lockMode == "none") {
            unlink(file.c_str());
        }
    }
}

// Write the passcode file in full under a temporary name, then move it into
// place, so the file is always either the old one or the new one.
bool Security::writePasscode(const std::string& mode, const std::string& hash) const
{
    const std::string file = passcodeFile();
    const std::string tmp = file + ".tmp";

    json_object* saved = json_object_new_object();
    json_object_object_add(saved, "version", json_object_new_int(s_passcodeVersion));
    json_object_object_add(saved, mode.c_str(), json_object_new_string(hash.c_str()));
    const char* buf = json_object_to_json_string(saved);

    // A temporary file left from before may have other permissions, or be a
    // link: start from none, and use nothing that appears in between.
    ::unlink(tmp.c_str());

    bool ok = false;
    int fd = ::open(tmp.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, S_IRUSR | S_IWUSR);
    if (fd != -1) {
        ok = writeAll(fd, buf, strlen(buf)) && ::fsync(fd) == 0;
        if (::close(fd) != 0)
            ok = false;
        if (ok)
            ok = ::rename(tmp.c_str(), file.c_str()) == 0;
    }

    if (ok) {
        // The rename is only durable once the directory is.
        int dir = ::open(authDataDir(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        if (dir != -1) {
            ::fsync(dir);
            ::close(dir);
        }
    }
    else {
        g_warning("%s: cannot save '%s': %s", __PRETTY_FUNCTION__, file.c_str(), g_strerror(errno));
        ::unlink(tmp.c_str());
    }

    json_object_put(saved);
    return ok;
}

void Security::eraseDevice()
{
    LSError err;
    LSErrorInit(&err);
    g_warning ("%s: calling %s", __func__, "palm://com.palm.storage/erase/Wipe");
    bool result = LSCallOneReply(m_service, "palm://com.palm.storage/erase/Wipe", "{}", &Security::cbDeviceWipe, this, NULL, &err);
    if (!result) {
        g_warning ("%s: Failed at %s with message %s", __func__, err.func, err.message);
        LSErrorFree (&err);
    }
}

bool Security::cbDeviceWipe (LSHandle*, LSMessage *message, void*)
{
    const char* str = LSMessageGetPayload(message);
    json_object *root = 0, *returnValue = 0;
    bool success = false;
    if (!str)
        goto done;

    root = json_tokener_parse(str);
    if (!root)
        goto done;

    returnValue = json_object_object_get (root, "returnValue");
    if (!returnValue) {
        g_warning ("%s: No return value", __func__);
        goto done;
    }

    success = json_object_get_boolean (returnValue);

done:
    if (root)
        json_object_put (root);

    if (success) {
        g_warning ("%s: wipe call succeeded, exiting now", __func__);
        exit(-2);
    }
    g_warning ("%s: Wipe failed", __func__);
    return true;
}


bool Security::passcodeSatisfiesPolicy(const EASPolicy * const policy) const
{
    // no policy to enforce or no PIN/password required
    if (!policy || !policy->passwordRequired())
        return true;

    // Only a hash of the passcode is kept, so whether it meets the policy's
    // rules cannot be told: it has to be set again under the policy.
    return false;
}

// Reject a run of repeated (aaaa) or sequential (1234, dcba) characters
// longer than half the passcode.
static int validateStrength(const QString& passcode)
{
    const int MaxSequence = passcode.length() / 2;
    int direction = 0;
    int j = 0;

    for (int i=0; i<passcode.length()-1; i++) {

        // should we start tracking a sequence?
        QChar curChar = passcode.at(i);
        QChar nextChar = passcode.at(i+1);
        direction = nextChar.unicode() - curChar.unicode();

        if (direction > -2 && direction < 2) {

            int numSequence = 2;
            curChar = nextChar;
            for (j=i+2; j<passcode.length(); j++) {

                // does the sequence continue?
                nextChar = passcode.at(j);
                int diff = nextChar.unicode() - curChar.unicode();
                if (diff != direction)
                    break;

                numSequence++;

                if (numSequence > MaxSequence) {
                    if (diff == 0)
                        return Security::FailureWeakPasswordRepeat;
                    else
                        return Security::FailureWeakPasswordSequence;
                }

                curChar = nextChar;
            }

            // skip characters we've already examined
            i = j-1;
        }
    }
    return Security::Success;
}

int Security::validatePasscode(const EASPolicy * const policy,    const std::string& mode,
    const std::string& passcode) const
{
    if (policy == 0 || !policy->passwordRequired())
        return Success;

    if (mode == "none" || passcode.empty())
        return FailureEmptyPasscode;

    // min length
    if (policy->validMinLength() && passcode.size() < policy->minLength())
        return FailureMinLength;

    QString pass = QString::fromUtf8(passcode.c_str());

    if (policy->requiresAlphaNumeric()) {

        // an alphanumeric password MUST be set
        if (mode != "password")
            return FailureInvalidPassword;

        // contains alpha numeric characters
        bool containsAlpha = false, containsNumeric = false;
        for (int i=0; i<pass.length(); i++) {

            if (!containsAlpha)
                containsAlpha = pass.at(i).isLetter();
            if (!containsNumeric)
                containsNumeric = pass.at(i).isNumber();

            if (containsAlpha && containsNumeric)
                break;
        }

        if (!containsAlpha || !containsNumeric)
            return FailureAlphaNumeric;
    }
    else {
        // password's can contain any character types
        if (mode == "pin") {
            // pin's must contain only digits
            for (int i=0; i<pass.length(); i++) {
                if (!pass.at(i).isNumber())
                    return FailureInvalidPin;
            }
        }
    }

    if (!policy->allowSimplePassword())
        return validateStrength(pass);

    return Success;
}
