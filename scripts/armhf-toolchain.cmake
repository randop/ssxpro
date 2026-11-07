# ARMHF: armv7 hard-float cross-compilation.
# Debian GCC already knows its target sysroot.
# Do NOT set CMAKE_SYSROOT.

set(CMAKE_SYSTEM_NAME Linux)
set(CMAKE_SYSTEM_PROCESSOR arm)

set(CMAKE_C_COMPILER arm-linux-gnueabihf-gcc)
set(CMAKE_CXX_COMPILER arm-linux-gnueabihf-g++)
set(CMAKE_ASM_COMPILER arm-linux-gnueabihf-gcc)

set(CMAKE_AR arm-linux-gnueabihf-ar)
set(CMAKE_RANLIB arm-linux-gnueabihf-ranlib)

set(CMAKE_C_FLAGS
    "-ffunction-sections -fdata-sections -fPIC -march=armv7-a -mfpu=vfpv3-d16 -mfloat-abi=hard"
)

set(CMAKE_CXX_FLAGS
    "-ffunction-sections -fdata-sections -fPIC -march=armv7-a -mfpu=vfpv3-d16 -mfloat-abi=hard"
)

set(CMAKE_ASM_FLAGS
    "-ffunction-sections -fdata-sections -fPIC -march=armv7-a -mfpu=vfpv3-d16 -mfloat-abi=hard"
)

