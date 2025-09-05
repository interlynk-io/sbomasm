#!/usr/bin/env bash
#
# A command to generate an agent prompt to diagnose and formulate
# a plan for resolving a GitHub issue.
#
# IMPORTANT: This command is prompted to NOT write any code and to ONLY
# produce a plan. You should still be vigilant when running this but that
# is the expected behavior.
#
# The `<issue>` parameter can be either an issue number or a full GitHub
# issue URL.
#
# NOTE: This script assumes you are inside a git repo with a valid
# GitHub remote configured.

set -euo pipefail

usage() {
  cat <<USAGE
Usage: $(basename "$0") <issue-number-or-url>

Example:
  $(basename "$0") 219
  $(basename "$0") https://github.com/interlynk-io/sbomasm/issues/219

This prints a detailed prompt (to stdout) for an assistant to:
 - Deep-dive on the issue
 - Explain the problem
 - Produce a comprehensive plan (NO CODE)
USAGE
  exit 1
}

if [[ $# -eq 0 ]]; then
  usage
fi

ISSUE="$1"

# Ensure dependencies
for dep in gh jq git; do
  if ! command -v "$dep" >/dev/null 2>&1; then
    echo "Error: '$dep' is required but not found in PATH." >&2
    exit 2
  fi
done

# Detect repo from current git remote
REMOTE_URL=$(git config --get remote.origin.url || true)
if [[ -z "$REMOTE_URL" ]]; then
  echo "Error: No remote.origin.url found. Run this inside a cloned GitHub repo." >&2
  exit 3
fi

# Normalize remote URL into "owner/repo"
if [[ "$REMOTE_URL" =~ ^git@github.com:(.+)\.git$ ]]; then
  REPO="${BASH_REMATCH[1]}"
elif [[ "$REMOTE_URL" =~ ^https://github.com/(.+)\.git$ ]]; then
  REPO="${BASH_REMATCH[1]}"
elif [[ "$REMOTE_URL" =~ ^https://github.com/(.+)$ ]]; then
  REPO="${BASH_REMATCH[1]}"
else
  echo "Error: Unsupported remote URL format: $REMOTE_URL" >&2
  exit 3
fi

# Fetch issue data
if ! ISSUE_JSON=$(gh issue view "$ISSUE" --repo "$REPO" --json author,title,number,body,comments 2>/dev/null); then
  echo "Error: failed to fetch issue from GitHub. Check repo/issue and that you have gh auth configured." >&2
  exit 4
fi

TITLE=$(jq -r '.title // ""' <<<"$ISSUE_JSON")
NUMBER=$(jq -r '.number // ""' <<<"$ISSUE_JSON")
BODY=$(jq -r '.body // ""' <<<"$ISSUE_JSON")
COMMENTS=$(jq -r '
  if (.comments | length) > 0 then
    [.comments[] | ("### Comment by (" + (.author.login // "unknown") + ")\n\n" + (.body // ""))] | join("\n\n")
  else
    ""
  end
' <<<"$ISSUE_JSON")
[[ -z "$COMMENTS" ]] && COMMENTS="(no comments)"
ISSUE_URL="https://github.com/${REPO}/issues/${NUMBER}"

# Print prompt
printf '%s\n\n' "Deep-dive on this GitHub issue. Find the problem and generate a plan.
Do not write code. Explain the problem clearly and propose a comprehensive plan
to solve it."

printf '# %s (%s)\n\n' "$TITLE" "$NUMBER"
printf '## Description\n%s\n\n' "$BODY"
printf '## Comments\n%s\n\n' "$COMMENTS"

cat <<'TASKS'

## Your Tasks

You are an experienced software developer tasked with diagnosing issues.

1. Review the issue context and details.
2. Examine the relevant parts of the codebase. Analyze the code thoroughly
   until you have a solid understanding of how it works.
3. Explain the issue in detail, including the problem and its root cause.
4. Create a comprehensive plan to solve the issue. The plan should include:
   - Required code changes
   - Potential impacts on other parts of the system
   - Necessary tests to be written or updated
   - Documentation updates
   - Performance considerations
   - Security implications
   - Backwards compatibility (if applicable)
   - Include the reference link to the source issue and any related discussions
5. Think deeply about all aspects of the task. Consider edge cases, potential
   challenges, and best practices for addressing the issue. Review the plan
   with the oracle and adjust it based on its feedback.

**ONLY CREATE A PLAN. DO NOT WRITE ANY CODE.** Your task is to create
a thorough, comprehensive strategy for understanding and resolving the issue.
TASKS

printf '\nSource: %s\n' "$ISSUE_URL"
