# Updating

"Upstream" is this repository itself: the published images `packaging/images.lock` pins, which
`packaging/pin_images.py` writes into `startos/spec.ts` (`IMAGES`). There is no external image to track.

## A new version

1. Publish the images (the "Publish images" workflow, or `scripts/oci_publish.sh`), then run
   `packaging/pin_images.py`, which writes the new pins into `startos/spec.ts` and every compose file.
2. Bump the Umbrel app's version to match.
3. Add a `startos/versions/v<version>.ts` with release notes (and a migration if the data layout changed:
   docs/CONTAINER.md is the contract), make it `current`, and move the old one to `other`.
4. `packaging/startos/test-startos.sh` (build, inspect, regtest), then publish to the registry (`docs/STARTOS.md`).
