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

# The daemon's own objects (authmanager-core: everything but main() and
# Src/Platform.cpp), linked with stand-ins for luna-service2 and for the
# platform seam (fakes/) instead of libluna-service2 and Platform.cpp.

find_package(GTest REQUIRED)

set(AUTH_SANITIZE "" CACHE STRING
    "Sanitizers for the test build, as -fsanitize= takes them (address,undefined or thread)")

add_executable(authmanager-tests
    $<TARGET_OBJECTS:authmanager-core>
    fakes/fakebus.cpp
    fakes/fakeplatform.cpp
    unit/main.cpp
    unit/fixture.cpp
    unit/test_passcode.cpp
    unit/test_lockout.cpp
    unit/test_methods.cpp
    unit/test_policy.cpp
    unit/test_change.cpp
    unit/test_token.cpp
    unit/test_persist.cpp
    unit/test_biometric.cpp)

target_include_directories(authmanager-tests PRIVATE fakes unit)
target_compile_options(authmanager-tests PRIVATE -Wextra)
target_compile_definitions(authmanager-tests PRIVATE AUTH_SOURCE_DIR="${CMAKE_SOURCE_DIR}")

target_link_libraries(authmanager-tests
    GTest::gtest
    ${GLIB2_LDFLAGS}
    ${JSON_LDFLAGS}
    ${XCRYPT_LDFLAGS}
    Qt::Core
    pthread)

if (AUTH_SANITIZE)
    set(AUTH_SANITIZE_FLAGS -fsanitize=${AUTH_SANITIZE})
    foreach(t authmanager-core authmanager-tests)
        target_compile_options(${t} PRIVATE ${AUTH_SANITIZE_FLAGS} -fno-omit-frame-pointer
                               -fno-sanitize-recover=all)
    endforeach()
    target_link_options(authmanager-tests PRIVATE ${AUTH_SANITIZE_FLAGS})
endif()

add_test(NAME authmanager-tests COMMAND authmanager-tests)
