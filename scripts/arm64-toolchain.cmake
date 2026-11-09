# ARM64: AArch64 GNU/Linux cross-compilation.
# Debian GCC already knows its target sysroot.
# Do NOT set CMAKE_SYSROOT.

set(CMAKE_SYSTEM_NAME Linux)
set(CMAKE_SYSTEM_PROCESSOR aarch64)

set(CMAKE_C_COMPILER aarch64-linux-gnu-gcc)
set(CMAKE_CXX_COMPILER aarch64-linux-gnu-g++)
set(CMAKE_ASM_COMPILER aarch64-linux-gnu-gcc)

set(CMAKE_AR aarch64-linux-gnu-ar)
set(CMAKE_RANLIB aarch64-linux-gnu-ranlib)

set(CMAKE_C_FLAGS
    "-ffunction-sections -fdata-sections -fPIC"
)

set(CMAKE_CXX_FLAGS
    "-ffunction-sections -fdata-sections -fPIC"
)

set(CMAKE_ASM_FLAGS
    "-ffunction-sections -fdata-sections -fPIC"
)

