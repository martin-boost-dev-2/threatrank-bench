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

# ---------------------------------------------------------------------------
# Worker sweep: the two concurrency knobs, at a fixed CVE count.
#
# ONNX inference runs behind a single mutex-guarded session, so raising
# ONNXWorkers should do nothing; snippet extraction is lock-free Go and may
# scale until it runs out of cores. This measures both rather than assuming.
# ---------------------------------------------------------------------------
workers_sweep() {
    local cap=${WORKER_SWEEP_CVES:-100}
    cp "$REPO_DIR/trivy-report.json" "$REPO_DIR/.trivy-full.json"
    python3 scripts/truncate_cves.py "$REPO_DIR/.trivy-full.json" \
        "$REPO_DIR/trivy-report.json" "$cap"

    local cves; cves=$(cve_count)
    say "  worker sweep at ${cves} CVEs on $(nproc) cores"
    row "$TARGET" "cores" "" "$(nproc)" "shape"

    for combo in ${WORKER_COMBOS:-"16:8" "16:1" "16:4" "16:16" "4:8" "32:8" "64:16"}; do
        local sw=${combo%%:*} ow=${combo##*:}

        local start stop secs
        start=$(now)
        docker run --rm -i -v "$REPO_DIR:/scan" -w /scan \
            -e THREATRANK_BENCHMARK=1 \
            -e THREATRANK_SNIPPET_WORKERS="$sw" \
            -e THREATRANK_ONNX_WORKERS="$ow" \
            "$VARIANT_B_IMAGE" process \
            < "$REPO_DIR/trivy-cyclonedx.json" > /dev/null 2>"$REPO_DIR/.arm.log" || true
        stop=$(now)
        secs=$(elapsed "$start" "$stop")

        local bench; bench=$(grep -o 'seconds=[0-9.]*' "$REPO_DIR/.arm.log" | head -1 || true)
        say "  snippet=${sw} onnx=${ow}: ${secs}s (${bench})"
        row "$TARGET" "workers-s${sw}-o${ow}" "$cves" "$secs" "${bench:-}"
    done

    mv "$REPO_DIR/.trivy-full.json" "$REPO_DIR/trivy-report.json"
}

# ---------------------------------------------------------------------------
# CPU sweep: is the machine already busy, or idle behind the inference mutex?
#
# ONNX Runtime is built with nil SessionOptions, so it uses its own default
# intra-op threading. If that already saturates the cores, capping the container
# to one CPU should slow it roughly by the core count; if inference really is
# single-threaded behind the mutex, capping it should change almost nothing.
# ---------------------------------------------------------------------------
cpu_sweep() {
    local cap=${WORKER_SWEEP_CVES:-100}
    cp "$REPO_DIR/trivy-report.json" "$REPO_DIR/.trivy-full.json"
    python3 scripts/truncate_cves.py "$REPO_DIR/.trivy-full.json" \
        "$REPO_DIR/trivy-report.json" "$cap"

    local cves; cves=$(cve_count)
    say "  cpu sweep at ${cves} CVEs on $(nproc) cores"

    for cpus in ${CPU_LIMITS:-1 2 4}; do
        local start stop secs
        start=$(now)
        docker run --rm -i --cpus="$cpus" -v "$REPO_DIR:/scan" -w /scan \
            -e THREATRANK_BENCHMARK=1 "$VARIANT_B_IMAGE" process \
            < "$REPO_DIR/trivy-cyclonedx.json" > /dev/null 2>"$REPO_DIR/.arm.log" || true
        stop=$(now)
        secs=$(elapsed "$start" "$stop")

        local bench; bench=$(grep -o 'seconds=[0-9.]*' "$REPO_DIR/.arm.log" | head -1 || true)
        say "  cpus=${cpus}: ${secs}s (${bench})"
        row "$TARGET" "cpus-${cpus}" "$cves" "$secs" "${bench:-}"
    done

    mv "$REPO_DIR/.trivy-full.json" "$REPO_DIR/trivy-report.json"
}

# ---------------------------------------------------------------------------
# Session-pool sweep: N single-threaded sessions against one multi-threaded one.
# Unset THREATRANK_ONNX_SESSIONS is the shipped behaviour and the baseline here.
# ---------------------------------------------------------------------------
pool_sweep() {
    local cap=${WORKER_SWEEP_CVES:-100}
    cp "$REPO_DIR/trivy-report.json" "$REPO_DIR/.trivy-full.json"
    python3 scripts/truncate_cves.py "$REPO_DIR/.trivy-full.json" \
        "$REPO_DIR/trivy-report.json" "$cap"

    local cves; cves=$(cve_count)
    say "  pool sweep at ${cves} CVEs on $(nproc) cores"

    for n in ${POOL_SIZES:-0 2 4 8}; do
        local envflag=()
        local label="baseline"
        if [ "$n" -gt 0 ]; then
            envflag=(-e "THREATRANK_ONNX_SESSIONS=$n")
            label="pool${n}"
        fi

        local start stop secs
        start=$(now)
        docker run --rm -i -v "$REPO_DIR:/scan" -w /scan \
            -e THREATRANK_BENCHMARK=1 "${envflag[@]}" "$VARIANT_B_IMAGE" process \
            < "$REPO_DIR/trivy-cyclonedx.json" > /dev/null 2>"$REPO_DIR/.arm.log" || true
        stop=$(now)
        secs=$(elapsed "$start" "$stop")

        local bench; bench=$(grep -o 'seconds=[0-9.]*' "$REPO_DIR/.arm.log" | head -1 || true)
        say "  ${label}: ${secs}s (${bench})"
        row "$TARGET" "$label" "$cves" "$secs" "${bench:-}"
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

    if [ "${RUN_WORKER_SWEEP:-0}" = "1" ]; then
        workers_sweep
    fi

    if [ "${RUN_CPU_SWEEP:-0}" = "1" ]; then
        cpu_sweep
    fi

    if [ "${RUN_POOL_SWEEP:-0}" = "1" ]; then
        pool_sweep
    fi

    say "== ${TARGET} done =="
}

main
