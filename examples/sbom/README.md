# Getting SBOMs to check

oss-intake reads CycloneDX or SPDX JSON, one file or a folder of them. These recipes produce that folder from the
tools most organisations already have. Each gives package-level data (package URLs), which is what oss-intake
checks; console inventories that list installed applications by name are not a substitute.

```bash
oss-intake --path ./sboms --out ./reports --label owner="Platform team"
```

## Amazon Inspector (EC2, ECR images, Lambda)

Inspector exports one SBOM per resource it monitors, to an S3 bucket encrypted with a KMS key (the bucket and key
used for findings export work). See [Exporting SBOMs with Amazon Inspector](https://docs.aws.amazon.com/inspector/latest/user/sbom-export.html).

```bash
aws inspector2 create-sbom-export --report-format CYCLONEDX_1_4 \
  --s3-destination bucketName=my-sbom-bucket,keyPrefix=inspector,kmsKeyArn=arn:aws:kms:REGION:ACCOUNT:key/KEY-ID
aws inspector2 get-sbom-export --report-id REPORT-ID          # wait for SUCCEEDED
aws s3 sync s3://my-sbom-bucket/inspector ./inspector-export
oss-intake --path ./inspector-export --out ./reports      # subfolders are read too
```

Check the first run's "SBOM components not checked" section. Inspector's OS package URLs
(`pkg:dpkg/libss2@...?upstream=libss2-1.44.5-1+deb10u3.src.dpkg`) may not name the distro release, and those are
listed there rather than guessed; so are Amazon Linux packages, since OSV has no Amazon Linux data (Inspector
itself covers those). Language packages are checked either way.

## Syft or Trivy (hosts, images, folders; on-premises and other clouds)

```bash
mkdir -p sboms
syft scan dir:/ -o cyclonedx-json=sboms/$(hostname).cdx.json                   # a Linux host
syft scan registry:ghcr.io/owner/app:1.2.3 -o cyclonedx-json=sboms/app-1.2.3.cdx.json
trivy image --format cyclonedx --output sboms/app-1.2.3.cdx.json ghcr.io/owner/app:1.2.3
trivy rootfs --format cyclonedx --output sboms/$(hostname).cdx.json /
```

Pin and verify the tool as for the scanners (see the main README). Both write the distro release and source
package that oss-intake needs for OS packages. On a host, `syft scan dir:/` also finds root file systems nested
inside it (container layers, chroots); a package whose type does not match the distro it is labelled with is
listed as not checked. `trivy rootfs` downloads Trivy's Java database when the host has JAR files, so it needs
network access to ghcr.io.

## GitHub dependency graph (every repository in an organisation)

```bash
mkdir -p sboms
gh repo list ORG --limit 1000 --json nameWithOwner -q '.[].nameWithOwner' | while read -r repo; do
  gh api "repos/$repo/dependency-graph/sbom" > "sboms/${repo//\//_}.json" || rm -f "sboms/${repo//\//_}.json"
done
```

The dependency graph must be enabled on each repository; the export is SPDX 2.3 and is read as is.

## Re-scan weekly

Commit the folder (or have a job refresh it) and point the
[scheduled re-scan workflow](../scheduled-rescan/oss-intake-rescan.yml) at it by setting `INVENTORY: sboms`.
