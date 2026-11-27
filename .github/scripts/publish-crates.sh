#!/usr/bin/env bash
#
# Publishes all publishable crates of the workspace with one `cargo publish`.
#
# Cargo packages and builds every crate before it uploads the first one, so a
# crate that does not build stops the run with nothing published. The uploads
# then go in dependency order. If one of them fails, the crates uploaded before
# it stay on crates.io: fix the cause and run again with `--resume`, which
# skips the crates whose version is already on crates.io.
#
# crates.io limits how fast new crates can be published (5 at once, then one
# every 10 minutes). When it answers with HTTP 429, the script waits and goes on
# with the remaining crates by itself.
#
# Usage: publish-crates.sh [--dry-run] [--resume]

set -euo pipefail

dry_run=()
resume=

for arg in "$@"; do
    case "$arg" in
        --dry-run) dry_run=(--dry-run) ;;
        --resume) resume=1 ;;
        *) echo "Unknown argument: $arg" >&2; exit 1 ;;
    esac
done

# Prints `<name> <version> <workspace dependencies...>` for each publishable
# crate of the workspace.
crates() {
    cargo metadata --format-version=1 --no-deps \
        | jq -r '.packages[] | select(.publish != [])
            | [.name, .version, (.dependencies[] | select(.kind != "dev" and .path != null) | .name)]
            | join(" ")'
}

# Succeeds if version `$2` of crate `$1` is in the crates.io index.
# Fails if it is not, or if the index cannot be read; cargo then refuses
# to publish a version that does exist.
published() {
    local name=${1,,} path

    case ${#name} in
        1) path=1/$name ;;
        2) path=2/$name ;;
        3) path=3/${name:0:1}/$name ;;
        *) path=${name:0:2}/${name:2:2}/$name ;;
    esac

    curl -sf "https://index.crates.io/$path" \
        | jq -e --arg version "$2" 'select(.vers == $version)' > /dev/null
}

log=$(mktemp)

while true; do
    packages=(--workspace)

    if [ -n "$resume" ]; then
        # Not read through `< <(crates)`, so that `set -e` sees a failure
        list=$(crates)

        if [ -z "$list" ]; then
            echo "No publishable crates found" >&2
            exit 1
        fi

        declare -A skipped=()
        packages=()

        while read -r name version deps; do
            if published "$name" "$version"; then
                echo "Skipping $name $version: already on crates.io"
                skipped[$name]=$deps
            else
                packages+=(-p "$name")
            fi
        done <<< "$list"

        # Cargo uploads a crate only after its dependencies, so a release that
        # stopped part way has no crate on crates.io without its dependencies
        for name in "${!skipped[@]}"; do
            read -ra deps <<< "${skipped[$name]}"

            for dep in "${deps[@]}"; do
                if [ -z "${skipped[$dep]+x}" ]; then
                    echo "Not resuming: $name is on crates.io but its dependency $dep" \
                        "is not; was the version bumped?" >&2
                    exit 1
                fi
            done
        done

        if [ ${#packages[@]} -eq 0 ]; then
            echo "All crates are already on crates.io"
            exit 0
        fi
    fi

    status=0
    cargo publish "${dry_run[@]}" "${packages[@]}" 2>&1 | tee "$log" || status=$?

    if [ $status -eq 0 ]; then
        exit 0
    fi

    if ! grep -q "status 429" "$log"; then
        exit $status
    fi

    echo "crates.io rate limit reached; publishing the remaining crates in 10 minutes"
    sleep 600
    resume=1
done
