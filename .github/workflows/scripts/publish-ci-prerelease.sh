#!/usr/bin/env bash
set -euo pipefail

: "${GH_TOKEN:?GH_TOKEN is required}"
: "${GITHUB_REPOSITORY:?GITHUB_REPOSITORY is required}"
: "${GITHUB_SHA:?GITHUB_SHA is required}"
: "${GITHUB_RUN_ID:?GITHUB_RUN_ID is required}"
: "${GITHUB_REF_NAME:?GITHUB_REF_NAME is required}"
: "${RUNNER_TEMP:?RUNNER_TEMP is required}"

readonly automatic_tag_prefix='ci-build-'
readonly retained_release_count=3
readonly driver_wait_timeout_seconds=3000
readonly warning_text='使用未经完全测试的版本可能导致：程序崩溃，系统死锁，系统崩溃，文件丢失，硬件损坏等严重后果。'

readonly -a expected_artifacts=(
  'KswordUserMode-unsigned-Release'
  'KswordSetup-unsigned-Release'
  'KswordARKLight-unsigned-Release'
  'KswordCheatEnginePlugin-x64-Release'
  'KswordCheatEnginePlugin-Win32-Release'
  'KswordCheatEngineLauncher-Release'
  'KswordARKDriver-unsigned-Release'
)

# Wait for the independently triggered driver workflow for this exact push.
# A user-mode CI success must not publish an automatic release while the R0
# build is still running or after it has failed.
driver_run_id=''
driver_deadline=$((SECONDS + driver_wait_timeout_seconds))
while (( SECONDS < driver_deadline )); do
  driver_run="$({
    gh api --method GET \
      -H 'Accept: application/vnd.github+json' \
      "/repos/$GITHUB_REPOSITORY/actions/workflows/driver-ci.yml/runs" \
      -f branch="$GITHUB_REF_NAME" \
      -f event=push \
      -f per_page=100 \
      --jq "[.workflow_runs[] | select(.head_sha == \"$GITHUB_SHA\")][0] // {} | [(.id // 0), (.status // \"missing\"), (.conclusion // \"none\")] | @tsv"
  } 2>&1)" || {
    echo "Unable to query Driver CI for $GITHUB_SHA: $driver_run" >&2
    exit 1
  }

  IFS=$'\t' read -r driver_run_id driver_status driver_conclusion <<< "$driver_run"
  echo "Driver CI for $GITHUB_SHA: id=$driver_run_id status=$driver_status conclusion=$driver_conclusion"

  if [[ "$driver_status" == 'completed' ]]; then
    if [[ "$driver_conclusion" != 'success' ]]; then
      echo "Driver CI did not succeed; automatic release is blocked." >&2
      exit 1
    fi
    break
  fi

  sleep 15
done

if [[ -z "$driver_run_id" || "$driver_run_id" == '0' || "$driver_status" != 'completed' ]]; then
  echo "Timed out waiting for Driver CI to complete for $GITHUB_SHA." >&2
  exit 1
fi

release_assets="$RUNNER_TEMP/ksword-ci-release-assets"
release_notes="$RUNNER_TEMP/ksword-ci-release-notes.md"
provenance_file="$release_assets/artifact-provenance.md"
mkdir -p "$release_assets"

{
  echo '# Automatic CI release artifact provenance'
  echo
  echo "Release commit: \`$GITHUB_SHA\`"
  echo
  echo '| Artifact | Source commit | Actions run | Created at |'
  echo '| --- | --- | ---: | --- |'
} > "$provenance_file"

# Range-based CI may skip unchanged projects. For each named component, select
# the current run's artifact when that project was affected. Only unchanged,
# skipped projects may reuse a non-expired artifact whose source commit is the
# release commit itself or one of its ancestors.
for artifact_name in "${expected_artifacts[@]}"; do
  preferred_run_id="$GITHUB_RUN_ID"
  require_preferred_artifact='false'
  case "$artifact_name" in
    'KswordUserMode-unsigned-Release')
      require_preferred_artifact="${CURRENT_USERMODE_REQUIRED:-false}"
      ;;
    'KswordSetup-unsigned-Release')
      require_preferred_artifact="${CURRENT_SETUP_REQUIRED:-false}"
      ;;
    'KswordARKLight-unsigned-Release')
      require_preferred_artifact="${CURRENT_ARKLIGHT_REQUIRED:-false}"
      ;;
    'KswordCheatEnginePlugin-x64-Release'|'KswordCheatEnginePlugin-Win32-Release')
      require_preferred_artifact="${CURRENT_CE_PLUGIN_REQUIRED:-false}"
      ;;
    'KswordCheatEngineLauncher-Release')
      require_preferred_artifact="${CURRENT_CE_LAUNCHER_REQUIRED:-false}"
      ;;
    'KswordARKDriver-unsigned-Release')
      preferred_run_id="$driver_run_id"
      ;;
  esac

  artifact_record="$({
    gh api --method GET \
      -H 'Accept: application/vnd.github+json' \
      "/repos/$GITHUB_REPOSITORY/actions/runs/$preferred_run_id/artifacts" \
      -f per_page=100 \
      --jq "[.artifacts[] | select(.expired == false and .name == \"$artifact_name\")][0] // {} | [(.id // 0), (.workflow_run.id // 0), (.workflow_run.head_sha // \"missing\"), (.created_at // \"missing\")] | @tsv"
  } 2>&1)" || {
    echo "Unable to query run $preferred_run_id for artifact $artifact_name: $artifact_record" >&2
    exit 1
  }

  IFS=$'\t' read -r artifact_id artifact_run_id artifact_sha artifact_created_at <<< "$artifact_record"
  if [[ -z "$artifact_id" || "$artifact_id" == '0' ]]; then
    if [[ "$require_preferred_artifact" == 'true' ]]; then
      echo "Current affected project did not upload its required artifact: $artifact_name" >&2
      exit 1
    fi

    artifact_candidates="$({
      gh api --method GET \
        -H 'Accept: application/vnd.github+json' \
        "/repos/$GITHUB_REPOSITORY/actions/artifacts" \
        -f name="$artifact_name" \
        -f per_page=100 \
        --jq ".artifacts[] | select(.expired == false and .workflow_run.head_branch == \"$GITHUB_REF_NAME\") | [.id, .workflow_run.id, .workflow_run.head_sha, .created_at] | @tsv"
    } 2>&1)" || {
      echo "Unable to query artifact $artifact_name: $artifact_candidates" >&2
      exit 1
    }

    artifact_id=0
    while IFS=$'\t' read -r candidate_id candidate_run_id candidate_sha candidate_created_at; do
      [[ -n "$candidate_id" && -n "$candidate_sha" ]] || continue
      comparison_status="$({
        gh api \
          -H 'Accept: application/vnd.github+json' \
          "/repos/$GITHUB_REPOSITORY/compare/$candidate_sha...$GITHUB_SHA" \
          --jq '.status'
      } 2>&1)" || {
        echo "Unable to compare artifact commit $candidate_sha with $GITHUB_SHA: $comparison_status" >&2
        exit 1
      }

      if [[ "$comparison_status" == 'identical' || "$comparison_status" == 'ahead' ]]; then
        artifact_id="$candidate_id"
        artifact_run_id="$candidate_run_id"
        artifact_sha="$candidate_sha"
        artifact_created_at="$candidate_created_at"
        break
      fi
      echo "Ignoring $artifact_name from non-ancestor commit $candidate_sha ($comparison_status)."
    done <<< "$artifact_candidates"
  fi
  if [[ -z "$artifact_id" || "$artifact_id" == '0' ]]; then
    echo "Required automatic release artifact is unavailable: $artifact_name" >&2
    exit 1
  fi

  artifact_archive="$release_assets/$artifact_name.zip"
  gh api \
    -H 'Accept: application/vnd.github+json' \
    "/repos/$GITHUB_REPOSITORY/actions/artifacts/$artifact_id/zip" \
    > "$artifact_archive"
  if [[ ! -s "$artifact_archive" ]]; then
    echo "Downloaded artifact is empty: $artifact_name" >&2
    exit 1
  fi

  printf '| `%s` | `%s` | `%s` | %s |\n' \
    "$artifact_name" "$artifact_sha" "$artifact_run_id" "$artifact_created_at" \
    >> "$provenance_file"
done

push_text="$({
  gh api \
    -H 'Accept: application/vnd.github+json' \
    "/repos/$GITHUB_REPOSITORY/commits/$GITHUB_SHA" \
    --jq '.commit.message | split("\n")[0]'
} 2>&1)" || {
  echo "Unable to read commit text for $GITHUB_SHA: $push_text" >&2
  exit 1
}
if [[ -z "$push_text" ]]; then
  push_text='(no commit text)'
fi

short_sha="${GITHUB_SHA:0:8}"
release_title="[CI Build] $short_sha:$push_text"
release_tag="${automatic_tag_prefix}${short_sha}-${GITHUB_RUN_ID}-${GITHUB_RUN_ATTEMPT:-1}"

{
  echo '> [!WARNING]'
  echo "> $warning_text"
  echo
  echo '此预发行版由 GitHub Actions 自动生成，包含未经签名的 CI 构建产物。'
  echo
  echo "- 提交：\`$GITHUB_SHA\`"
  echo "- CI：https://github.com/$GITHUB_REPOSITORY/actions/runs/$GITHUB_RUN_ID"
  echo "- Driver CI：https://github.com/$GITHUB_REPOSITORY/actions/runs/$driver_run_id"
  echo '- 资产来源详见 `artifact-provenance.md`。'
} > "$release_notes"

release_url="$({
  gh release create "$release_tag" "$release_assets"/* \
    --repo "$GITHUB_REPOSITORY" \
    --target "$GITHUB_SHA" \
    --title "$release_title" \
    --notes-file "$release_notes" \
    --prerelease
} 2>&1)" || {
  echo "Unable to create automatic prerelease: $release_url" >&2
  exit 1
}
echo "Created automatic prerelease: $release_url"

# Delete only releases carrying both of our automatic markers. Sort explicitly
# by creation timestamp so exactly the newest three automatic releases remain;
# manual prereleases and all normal releases are outside this cleanup scope.
mapfile -t automatic_releases < <(
  gh api --paginate \
    -H 'Accept: application/vnd.github+json' \
    "/repos/$GITHUB_REPOSITORY/releases?per_page=100" \
    --jq '.[] | select(.draft == false and .prerelease == true and (.tag_name | startswith("ci-build-")) and ((.name // "") | startswith("[CI Build] "))) | [.created_at, .tag_name] | @tsv' \
    | sort -r
)

for stale_release in "${automatic_releases[@]:retained_release_count}"; do
  stale_tag="${stale_release#*$'\t'}"
  echo "Deleting stale automatic prerelease: $stale_tag"
  gh release delete "$stale_tag" \
    --repo "$GITHUB_REPOSITORY" \
    --cleanup-tag \
    --yes
done

{
  echo '### Automatic prerelease'
  echo
  echo "- Release: $release_url"
  echo "- Title: $release_title"
  echo "- Retention: newest $retained_release_count automatic prereleases"
} >> "$GITHUB_STEP_SUMMARY"
