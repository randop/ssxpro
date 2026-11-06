# Kernel CI runners

The kernel matrix intentionally runs on self-hosted Linux runners because GitHub-hosted Ubuntu jobs cannot select or boot a specific host kernel. Register two ephemeral runners with labels:

* `self-hosted`, `linux`, `ssxpro-kernel-6-12`: boot Linux 6.12 LTS.
* `self-hosted`, `linux`, `ssxpro-kernel-stable`: boot the latest upstream stable kernel.

Both need Rust stable, CMake, a C/C++ compiler, and the standard Rust target dependencies required by quiche/BoringSSL. The workflow checks `uname -r` before building. Keep the stable runner updated to the latest upstream stable release and record its exact version in the job log. Do not use a container kernel version as a substitute for the runner host kernel.
