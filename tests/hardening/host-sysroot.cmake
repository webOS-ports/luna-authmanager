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

# The build host's own gcc or clang, compiling against an x86-64 recipe
# sysroot. The image toolchain ships no sanitizer runtimes; the host's do,
# and with the same glibc as the sysroot they run against its libraries.
#
#   DM_SYSROOT   <recipe workdir>/recipe-sysroot of the corei7-64 build
#   DM_HOST_CC   gcc or clang (default gcc)

# try_compile() re-reads this file in a project of its own.
list(APPEND CMAKE_TRY_COMPILE_PLATFORM_VARIABLES DM_SYSROOT DM_HOST_CC)

set(CMAKE_SYSTEM_NAME Linux)
set(CMAKE_SYSTEM_PROCESSOR x86_64)

if (NOT DM_HOST_CC)
    set(DM_HOST_CC gcc)
endif()
if (DM_HOST_CC STREQUAL "clang")
    set(CMAKE_C_COMPILER clang)
    set(CMAKE_CXX_COMPILER clang++)
    # The sysroot's gcc (crtbeginS.o, libgcc, libstdc++'s headers) is in a
    # Yocto triple directory clang does not look for on its own.
    file(GLOB DM_GCC_INSTALL_DIR LIST_DIRECTORIES true "${DM_SYSROOT}/usr/lib/x86_64-*-linux/*")
    set(CMAKE_C_FLAGS_INIT "--gcc-install-dir=${DM_GCC_INSTALL_DIR}")
    set(CMAKE_CXX_FLAGS_INIT "--gcc-install-dir=${DM_GCC_INSTALL_DIR}")
    set(CMAKE_EXE_LINKER_FLAGS_INIT "--gcc-install-dir=${DM_GCC_INSTALL_DIR}")
else()
    set(CMAKE_C_COMPILER gcc)
    set(CMAKE_CXX_COMPILER g++)
endif()

set(CMAKE_SYSROOT ${DM_SYSROOT})
set(CMAKE_FIND_ROOT_PATH ${DM_SYSROOT})
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)

# pkg-config is pointed at the sysroot by the caller's environment
# (PKG_CONFIG_SYSROOT_DIR, PKG_CONFIG_LIBDIR): see run-sanitizers.sh.
