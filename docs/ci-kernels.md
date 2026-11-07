<!-- coderabbit-ai-generated:v1 -->

<!-- coderabbit-ai-generated-section:v1:ab3444855ecd46321173a37b2f45556210635c48278c86b8e75ab7abc0002acd -->

# Kernel CI runners

The planned kernel matrix will run on self-hosted Linux runners because GitHub-hosted Ubuntu jobs cannot select or boot a specific host kernel. Register two ephemeral runners with labels:

* `self-hosted`, `linux`, `ssxpro-kernel-6-12`: boot Linux 6.12 LTS.
* `self-hosted`, `linux`, `ssxpro-kernel-stable`: boot the latest upstream stable kernel.

Both need Rust stable, CMake, a C/C++ compiler, and the standard Rust target dependencies required by quiche/BoringSSL. Until the workflow is added, operators must run `scripts/check-kernel-version.sh` on the corresponding host before building.

Keep the stable runner updated to the latest upstream stable release and record its exact version in the job log. Do not use a container kernel version as a substitute for the runner host kernel.

Before building, run each preflight on its corresponding host:

```sh
scripts/check-kernel-version.sh 6-12
scripts/check-kernel-version.sh stable "$EXPECTED_STABLE_RELEASE"
```

Set `EXPECTED_STABLE_RELEASE` explicitly to the required upstream `major.minor.patch` release. The stable check rejects a different release and separately requires Linux 6.12 or newer.

<!-- /coderabbit-ai-generated:v1 -->