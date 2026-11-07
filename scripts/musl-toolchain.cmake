# Cross toolchain file for fully static x86_64-unknown-linux-musl builds.
# Compiler names resolve through PATH; point cargo at another file with
# CMAKE_TOOLCHAIN_FILE_x86_64_unknown_linux_musl to use a different toolchain.
set(CMAKE_SYSTEM_NAME Linux)
set(CMAKE_SYSTEM_PROCESSOR x86_64)

set(CMAKE_C_COMPILER x86_64-unknown-linux-musl-gcc)
set(CMAKE_CXX_COMPILER x86_64-unknown-linux-musl-g++)
set(CMAKE_AR x86_64-unknown-linux-musl-ar)
set(CMAKE_RANLIB x86_64-unknown-linux-musl-ranlib)
