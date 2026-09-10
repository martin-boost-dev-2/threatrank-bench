#!/usr/bin/env bash
#
# Time the three arms of the ThreatRank cost question against one repository:
#
#   control   the SCA post-processor as it ships today
#   variantA  ThreatRank chained as a second post-processor (the PoC shape)
#   variantB  ThreatRank built into the SCA post-processor
#
# Emits one CSV row per measurement on stdout; everything else goes to stderr so
# the caller can redirect cleanly.
set -euo pipefail

REPO_DIR=${REPO_DIR:?set REPO_DIR to the checkout under test}
TARGET=${TARGET:?set TARGET to the repo name, for the report}
REPEATS=${REPEATS:-3}

TRIVY_VERSION=${TRIVY_VERSION:-0.69.2}
TRIVY_BIN=${TRIVY_BIN:-/usr/local/bin/trivy}
CONTROL_IMAGE=${CONTROL_IMAGE:?}
VARIANT_A_IMAGE=${VARIANT_A_IMAGE:?}
VARIANT_B_IMAGE=${VARIANT_B_IMAGE:?}
TRIVY_CONVERTER_IMAGE=${TRIVY_CONVERTER_IMAGE:?}

say() { printf '%s\n' "$*" >&2; }

# Seconds with millisecond resolution; `date +%s.%N` is GNU-only but the runner
# is Linux, and bash SECONDS is integer-only which is too coarse here.
now() { date +%s.%N; }
elapsed() { echo "$1 $2" | awk '{printf "%.2f", $2 - $1}'; }

row() { # target arm cves seconds note
    printf '%s,%s,%s,%s,%s\n' "$1" "$2" "$3" "$4" "$5"
}

# ---------------------------------------------------------------------------
# Repo shape, so cost can be read against size rather than just CVE count.
# ---------------------------------------------------------------------------
repo_stats() {
    local files loc
    files=$(find "$REPO_DIR" -type f -not -path '*/.git/*' | wc -l | tr -d ' ')
    loc=$(find "$REPO_DIR" -type f -not -path '*/.git/*' \
            \( -name '*.go' -o -name '*.py' -o -name '*.js' -o -name '*.ts' \
               -o -name '*.java' -o -name '*.rb' -o -name '*.cs' -o -name '*.php' \) \
            -exec cat {} + 2>/dev/null | wc -l | tr -d ' ')
    say "  repo: ${files} files, ${loc} lines of source"
    row "$TARGET" "repo-files" "" "$files" "shape"
    row "$TARGET" "repo-loc" "" "$loc" "shape"
}

# ---------------------------------------------------------------------------
# The Trivy scan itself — the cost every arm shares, and the baseline that
# reachability is a percentage *of*.
# ---------------------------------------------------------------------------
# The binary rather than the image: it is what the scanner module actually
# downloads, and it keeps the benchmark off Docker Hub's anonymous pull limit,
# which six parallel jobs exhaust.
install_trivy() {
    [ -x "$TRIVY_BIN" ] && return
    curl -sfSL -o /tmp/trivy.gz \
        "https://assets.build.boostsecurity.io/scanners/trivy/trivy-${TRIVY_VERSION}/linux/amd64/trivy.gz"
    gunzip -f /tmp/trivy.gz
    chmod +x /tmp/trivy
    sudo mv /tmp/trivy "$TRIVY_BIN"
}

run_trivy() {
    install_trivy

    local start stop
    start=$(now)
    ( cd "$REPO_DIR" && "$TRIVY_BIN" fs --format=json --output=trivy-report.json \
        --license-full --no-progress --scanners vuln --cache-dir=/tmp/trivy-cache \
        --skip-version-check . >/dev/null 2>&1 ) || true
    stop=$(now)

    ( cd "$REPO_DIR" && "$TRIVY_BIN" convert --quiet --format cyclonedx \
        trivy-report.json > trivy-cyclonedx.json 2>/dev/null ) || true

    local secs; secs=$(elapsed "$start" "$stop")
    say "  trivy scan: ${secs}s"
    row "$TARGET" "trivy-scan" "$(cve_count)" "$secs" "baseline"
}

cve_count() {
    python3 -c "
import json,sys
try:
    d=json.load(open('$REPO_DIR/trivy-report.json'))
except Exception:
    print(0); sys.exit()
print(sum(len(r.get('Vulnerabilities') or []) for r in d.get('Results') or []))
"
}

# ---------------------------------------------------------------------------
# The three arms. Each is timed as the CLI would run it: a container fed the
# scan output on stdin, with the repository bind-mounted where the module says.
# ---------------------------------------------------------------------------
time_arm() { # arm image extra_docker_args...
    local arm=$1 image=$2; shift 2
    local cves; cves=$(cve_count)

    for i in $(seq 1 "$REPEATS"); do
        local start stop secs
        start=$(now)
        docker run --rm -i -v "$REPO_DIR:/scan" -w /scan "$@" "$image" process \
            < "$REPO_DIR/trivy-cyclonedx.json" > /dev/null 2>"$REPO_DIR/.arm.log" || true
        stop=$(now)
        secs=$(elapsed "$start" "$stop")

        local bench; bench=$(grep -o 'BENCH threatrank [^|]*' "$REPO_DIR/.arm.log" | head -1 || true)
        say "  ${arm} run ${i}: ${secs}s ${bench}"
        row "$TARGET" "$arm" "$cves" "$secs" "${bench:-}"
    done
}

time_variant_a() {
    local cves; cves=$(cve_count)

    for i in $(seq 1 "$REPEATS"); do
        local start stop secs
        start=$(now)
        # The PoC chain: the Trivy converter's SARIF feeds the enricher, which
        # needs the repo mounted to build its call graph.
        docker run --rm -i -v "$REPO_DIR:/scan" -w /scan \
            "$TRIVY_CONVERTER_IMAGE" process < "$REPO_DIR/trivy-report.json" 2>/dev/null \
        | docker run --rm -i -v "$REPO_DIR:/src" -w /src \
            "$VARIANT_A_IMAGE" process > /dev/null 2>"$REPO_DIR/.arm.log" || true
        stop=$(now)
        secs=$(elapsed "$start" "$stop")
        say "  variantA run ${i}: ${secs}s"
        row "$TARGET" "variantA" "$cves" "$secs" ""
    done
}

# ---------------------------------------------------------------------------
# CVE sweep: same repository, truncated vulnerability list. Isolates per-CVE
# cost from call-graph cost, which otherwise move together.
# ---------------------------------------------------------------------------
sweep() {
    cp "$REPO_DIR/trivy-report.json" "$REPO_DIR/.trivy-full.json"

    for n in ${SWEEP_COUNTS:-10 25 50 100 250 500}; do
        python3 scripts/truncate_cves.py "$REPO_DIR/.trivy-full.json" \
            "$REPO_DIR/trivy-report.json" "$n"
        local actual; actual=$(cve_count || echo 0)
        if [ "${actual:-0}" -eq 0 ]; then
            continue
        fi

        local start stop secs
        start=$(now)
        docker run --rm -i -v "$REPO_DIR:/scan" -w /scan \
            -e THREATRANK_BENCHMARK=1 "$VARIANT_B_IMAGE" process \
            < "$REPO_DIR/trivy-cyclonedx.json" > /dev/null 2>"$REPO_DIR/.arm.log" || true
        stop=$(now)
        secs=$(elapsed "$start" "$stop")

        local bench; bench=$(grep -o 'seconds=[0-9.]*' "$REPO_DIR/.arm.log" | head -1 || true)
        say "  sweep ${actual} CVEs: ${secs}s (${bench})"
        row "$TARGET" "sweep" "$actual" "$secs" "${bench:-}"

        # Stop once the list is exhausted rather than re-timing the same set.
        if [ "$actual" -lt "$n" ]; then
            break
        fi
    done

    mv "$REPO_DIR/.trivy-full.json" "$REPO_DIR/trivy-report.json"
}

main() {
    say "== ${TARGET} =="
    repo_stats
    run_trivy

    if [ "${SWEEP_ONLY:-false}" != "true" ]; then
        time_arm "control" "$CONTROL_IMAGE"
        time_variant_a
        time_arm "variantB" "$VARIANT_B_IMAGE" -e THREATRANK_BENCHMARK=1
    fi

    if [ "${RUN_SWEEP:-0}" = "1" ]; then
        sweep
    fi

    say "== ${TARGET} done =="
}

main
