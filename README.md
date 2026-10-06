# Release control candidate

Generic release-decision validation only. This repository contains no product source, customer data, or deployment credentials.

Checks bind a tested revision, artifact digest and a trusted signed attestation. The validator cannot itself isolate shared owner credentials or prevent an existing deployment path from bypassing it. Deployment authority and bypass rejection must be verified separately before production use.

Run: `python3 -m unittest discover -v`
