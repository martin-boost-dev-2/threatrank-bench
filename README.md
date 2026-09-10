# threatrank-bench

CI timing harness for SPIKE #338: what would ThreatRank reachability analysis
add to an SCA scan?

Three arms, timed against real repositories:

- `control` — the SCA post-processor as it ships today
- `variantA` — ThreatRank chained as a second post-processor (the PoC shape)
- `variantB` — ThreatRank built into the SCA post-processor

Plus a CVE sweep on one repository, which holds the call graph fixed so
per-CVE cost can be separated from repo size.

Run `threatrank-bench` from the Actions tab with the variant-B image tag.
