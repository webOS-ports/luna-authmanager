# @@@LICENSE
#
#      Copyright (c) 2026 Herman van Hazendonk <github.com@herrie.org>
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# LICENSE@@@

cmake_minimum_required(VERSION 3.5)

project(luna-authmanager CXX)

set(CMAKE_INCLUDE_CURRENT_DIR ON)

include(webOS/webOS)
webos_modules_init(1 0 0 QUALIFIER RC3)
webos_component(1 0 0)

webos_add_compiler_flags(ALL -DQT_NO_KEYWORDS)

find_package(Qt6 COMPONENTS Core)
if (NOT Qt6_FOUND)
    find_package(Qt5 5.15 REQUIRED COMPONENTS Core)
endif()

include(FindPkgConfig)

pkg_check_modules(GLIB2 REQUIRED glib-2.0)
include_directories(${GLIB2_INCLUDE_DIRS})
webos_add_compiler_flags(ALL ${GLIB2_CFLAGS})

pkg_check_modules(LUNASERVICE2 REQUIRED luna-service2)
include_directories(${LUNASERVICE2_INCLUDE_DIRS})
webos_add_compiler_flags(ALL ${LUNASERVICE2_CFLAGS})

pkg_check_modules(JSON REQUIRED json-c)
include_directories(${JSON_INCLUDE_DIRS})
webos_add_compiler_flags(ALL ${JSON_CFLAGS})

# crypt(3) with yescrypt, for the passcode hash.
pkg_check_modules(XCRYPT REQUIRED libxcrypt)
include_directories(${XCRYPT_INCLUDE_DIRS})

webos_add_compiler_flags(ALL -Wall)

include_directories(Src)

# Everything but main() and the platform seam (Platform.cpp), so the tests
# can link the same objects with their own data directory and clock.
add_library(authmanager-core OBJECT
    Src/AuthService.cpp
    Src/Security.cpp
    Src/EASPolicyManager.cpp
    Src/UnlockToken.cpp)
target_link_libraries(authmanager-core PUBLIC Qt::Core)

add_executable(LunaAuthManager
    $<TARGET_OBJECTS:authmanager-core>
    Src/Platform.cpp
    Src/Main.cpp)

target_link_libraries(LunaAuthManager
    ${GLIB2_LDFLAGS}
    ${LUNASERVICE2_LDFLAGS}
    ${JSON_LDFLAGS}
    ${XCRYPT_LDFLAGS}
    Qt::Core
    pthread)

webos_build_daemon(NAME LunaAuthManager)
webos_build_system_bus_files()

option(BUILD_TESTING "Build the unit tests in tests/" OFF)
if (BUILD_TESTING)
    add_subdirectory(tests)
endif()
