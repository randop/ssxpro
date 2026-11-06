<!-- coderabbit-ai-generated:v1 -->

<!-- coderabbit-ai-generated-section:v1:4f8861673a6fa1849ccecb650e3edd7e01cf1d33e376c30b8e0c31f90505b741 -->

<!-- coderabbit-ai-generated-section:v1:13315c18a7f38e97496764824d58f571ccb85772a9cc9a25e8a952001d7a2d6f -->

# Kernel CI runners

The planned kernel matrix will run on self-hosted Linux runners because GitHub-hosted Ubuntu jobs cannot select or boot a specific host kernel. Register two ephemeral runners with labels:

* `self-hosted`, `linux`, `ssxpro-kernel-6-12`: boot Linux 6.12 LTS.
* `self-hosted`, `linux`, `ssxpro-kernel-stable`: boot the latest upstream stable kernel.

Both need Rust stable, CMake, a C/C++ compiler, and the standard Rust target dependencies required by quiche/BoringSSL. Until the workflow is added, operators must run `scripts/check-kernel-version.sh` on the corresponding host before building. Keep the stable runner updated to the latest upstream stable release and record its exact version in the job log. Do not use a container kernel version as a substitute for the runner host kernel.


<!-- /coderabbit-ai-generated:v1 -->