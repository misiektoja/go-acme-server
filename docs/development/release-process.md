# Release process

A release is started by pushing a version tag that is reachable from `main` and by nothing else.
`RELEASE_NOTES.md` carries one section per version and that section becomes the release
description.

## Versioning

The module follows semantic versioning under the [Compatibility policy](../reference/compatibility.md).
Before v1.0.0 a minor release may change the public API and the release notes name every such
change.

## Steps

1. On `dev`, add or complete the `## [X.Y.Z] - D Mon YYYY` section in `RELEASE_NOTES.md` and read it as a user of the library. Name the tested client versions.
2. Run the checks:

    ```bash
    make lint
    make test
    make test-interop
    make docs-build
    VERSION=vX.Y.Z make release-check
    ```

    The release check exports `HEAD` with `git archive`, verifies, builds and tests the export and imports it from a separate module, so it catches files that are ignored, untracked or only present locally. It also confirms that the release notes have a heading for the version and no unreleased section.

3. Merge `dev` into `main`, create a signed annotated tag and push `main` and the tag:

    ```bash
    git tag -s v0.1.0 -m 'v0.1.0'
    git push origin main v0.1.0
    ```

4. The release workflow repeats the release check on the tag, builds the source archives, the SBOM and the checksums, attests their provenance and creates a **draft** release with the release notes section as its description. Review the draft and publish it.
5. Confirm the module proxy serves the version and that pkg.go.dev shows the package documentation:

    ```bash
    GOPROXY=https://proxy.golang.org GOFLAGS=-mod=mod go list -m github.com/misiektoja/go-acme-server@vX.Y.Z
    ```

    Run it from a directory outside the repository.

!!! warning "Never draft a release in the GitHub UI"
    Drafting there creates the tag, which starts the workflow against a release that is already
    published. The workflow refuses to rebuild a published release, so the release and its tag have
    to be removed before the tag can be pushed properly.

## Artifacts

Each release carries:

| Artifact | Content |
| --- | --- |
| `go-acme-server-<version>-source.zip` and `.tar.gz` | The complete tagged source tree, including tests, documentation and CI configuration |
| `go-acme-server-<version>-sbom.cdx.json` | A CycloneDX software bill of materials with license information |
| `go-acme-server-<version>_SHA256SUMS.txt` | SHA-256 checksums of the archives and the SBOM |
| `go-acme-server-<version>.intoto.jsonl` | A signed provenance bundle covering the artifacts |

Verify a file with `gh attestation verify <file> --repo misiektoja/go-acme-server`. Offline
verification takes `--bundle` and the provenance file.

## Documentation

The documentation workflow publishes this site from the default branch to GitHub Pages whenever
`docs/` or `mkdocs.yml` changes there. Pull requests and pushes to `dev` run the strict build
without publishing. The site therefore always describes `main`, which is the latest release plus
any fixes merged since.
