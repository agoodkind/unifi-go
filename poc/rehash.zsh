#!/usr/bin/env zsh

set -euo pipefail

function main() {
    local artifact
    local relative_artifact
    local run_directory="${1:-}"
    local temporary_hash_file

    if [[ -z "$run_directory" || ! -d "$run_directory" ]]; then
        print -u2 -- "Usage: rehash.zsh RUN_DIRECTORY"
        return 2
    fi
    run_directory="${run_directory:A}"
    temporary_hash_file="$run_directory/.SHA256SUMS.tmp"
    : >"$temporary_hash_file"
    while IFS= read -r artifact; do
        if [[ "${artifact:t}" == "SHA256SUMS" || "$artifact" == "$temporary_hash_file" ]]; then
            continue
        fi
        relative_artifact="${artifact#$run_directory/}"
        (
            cd "$run_directory"
            shasum -a 256 "$relative_artifact"
        ) >>"$temporary_hash_file"
    done < <(find "$run_directory" -type f | LC_ALL=C sort)
    mv "$temporary_hash_file" "$run_directory/SHA256SUMS"
    chmod 600 "$run_directory/SHA256SUMS"
    print -- "REHASHED run=$run_directory"
}

main "$@"
