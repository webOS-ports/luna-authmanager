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

#include <glib.h>

#include <QCoreApplication>

#include "AuthService.h"
#include "Security.h"
#include "EASPolicyManager.h"

int main(int argc, char** argv)
{
    // Qt's UNIX event dispatcher drives the default GMainContext, so LS2
    // handles attached to this loop are serviced by app.exec() - the same
    // arrangement luna-sysmgr used.
    QCoreApplication app(argc, argv);

    GMainLoop* mainLoop = g_main_loop_new(NULL, FALSE);

    if (!AuthService::instance()->init(mainLoop)) {
        g_critical("Failed to register com.palm.systemmanager; refusing to run without it");
        return 1;
    }

    // Security's constructor reads the lock mode, registers the keymanager
    // companion name and subscribes to policy changes - it needs the bus up.
    (void) Security::instance();

    // Load and enforce whatever EAS policies are stored in db8.
    EASPolicyManager::instance()->load();

    return app.exec();
}
