Source: [.github/workflows/tests.yml](../../../../.github/workflows/tests.yml).
Maintain this document alongside its source file. When the source or relevant imported contracts change, verify and update this companion in the same change.

This CI entrypoint invokes the repository's authoritative test.sh on pushes to main/develop, pull requests and manual dispatch. It grants contents-read permission, runs on Ubuntu, and bounds the job to twenty minutes. New runs cancel older runs in the same workflow/ref concurrency group.

It does not define another test selection or provider acceptance lane. Check [test.sh](../../../../test.sh) and [Dockerfile.test](../../../../Dockerfile.test) for the actual dependency/network/cleanup behavior; a cancelled CI job is not a completed green or cleanup witness.
