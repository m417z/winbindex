#!/bin/bash

# Check if the repository path is provided
if [ -z "$1" ] || [ -z "$2" ]; then
  echo "Usage: $0 /path/to/repository keep_since_time"
  exit 1
fi

REPO_PATH=$1
KEEP_SINCE=$2  # e.g. "7 days ago"

# Change to the target repository
cd "$REPO_PATH" || { echo "Repository not found at $REPO_PATH"; exit 1; }

# Ensure the working directory is clean
if ! git diff-index --quiet HEAD --; then
  echo "Your working directory is not clean. Commit or stash your changes first."
  exit 1
fi

# Squash old commits
for i in $(git log --since="$KEEP_SINCE" --format=%H --reverse); do
  if [ -z "$new_commit" ]; then
    if [ "$(git rev-list "$i" --children)" == "$i" ]; then
        echo No commits to squash
        exit
    fi

    # How to remove only the first occurrence of a line in a file using sed: https://stackoverflow.com/q/23696871
    msg=$(git cat-file commit "$i" | sed "0,/^parent /{//d}")
    msg+=$'\n\n========================================\nSquashed history:\n\n'
    msg+=$(git log --first-parent "$i~" | sed -r 's/^[[:blank:]]+//')
  else
    msg=$(git cat-file commit "$i" | sed "s/$i_prev/$new_commit/")
  fi
  new_commit=$(echo "$msg" | git hash-object -t commit -w --stdin)
  echo "$i -> $new_commit"
  i_prev=$i
done

git reset $new_commit
