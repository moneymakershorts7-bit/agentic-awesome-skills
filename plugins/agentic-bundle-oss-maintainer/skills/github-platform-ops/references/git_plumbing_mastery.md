# Advanced Git Plumbing, History Diagnostics & Hygiene

Reference manual for deterministic Git plumbing, parallel branch automation (`git worktree`), conflict recording (`git rerere`), and automated bisection (`git bisect run`).

---

## 1. Git Plumbing Primitives: Low-Level Automation

Porcelain commands (`git commit`, `git add`, `git pull`) contain user-facing heuristics, interactive hooks, and color codes that make scripting brittle. Scripting against low-level plumbing commands guarantees atomic, deterministic behavior:

| Plumbing Command | Function / Purpose | Example Automation Usage |
| :--- | :--- | :--- |
| `git hash-object` | Writes data to `.git/objects` and returns SHA-1/SHA-256 hash. | `blob_sha=$(echo "hello" \| git hash-object -w --stdin)` |
| `git cat-file` | Inspects type (`-t`), size (`-s`), or contents (`-p`) of any object. | `git cat-file -p HEAD:package.json` |
| `git write-tree` | Creates a tree object from current index without committing. | `tree_sha=$(git write-tree)` |
| `git commit-tree` | Creates an atomic commit object pointing to a tree and parent(s). | `commit_sha=$(git commit-tree $tree_sha -p HEAD -m "feat: msg")` |
| `git update-ref` | Atomically updates a reference pointer to a commit SHA. | `git update-ref refs/heads/main $commit_sha` |
| `git rev-parse` | Resolves revisions, tags, and repo root paths safely. | `root=$(git rev-parse --show-toplevel)` |

### Creating an Atomic Commit Entirely via Plumbing:
```bash
# 1. Stage changes into index
git update-index --add --replace file.txt

# 2. Write index to tree object
tree_sha=$(git write-tree)

# 3. Create commit object
commit_sha=$(git commit-tree "$tree_sha" -p HEAD -m "feat(core): atomic automated commit")

# 4. Fast-forward current ref
git update-ref refs/heads/$(git rev-parse --abbrev-ref HEAD) "$commit_sha"
```

---

## 2. Parallel Development with Git Worktrees (`git worktree`)

Worktrees allow maintaining multiple live working trees linked to the same `.git` repository without cloning multiple times:

```bash
# 1. Create a isolated worktree for a feature branch
git worktree add ../feature-auth -b feat/auth-service

# 2. List active worktrees
git worktree list

# 3. Safely remove worktree after branch merge
git worktree remove ../feature-auth

# 4. Prune stale worktree references
git worktree prune
```

---

## 3. Conflict Recording & Reuse (`git rerere`)

`git rerere` (Reuse Recorded Resolution) remembers how you resolved a merge conflict hunk, automatically applying the same resolution in subsequent rebases or merges:

```bash
# Enable globally or per-repository
git config --global rerere.enabled true
git config --global rerere.autoUpdate true

# Inspect rerere cache
git rerere status
git rerere diff
```

---

## 4. Automated Bug Isolation with `git bisect run`

Automates binary search through Git history using a deterministic shell command or test suite:

```bash
# 1. Start bisect
git bisect start

# 2. Mark bad (current HEAD has the regression)
git bisect bad HEAD

# 3. Mark good (known good tag or commit)
git bisect good v1.2.0

# 4. Run automated test until culprit commit is identified
git bisect run npm test

# 5. Reset back to original branch state
git bisect reset
```

---

## 5. History Diagnostics & Reflog Recovery

```bash
# 1. Recover accidentally deleted branch or reset commit
git reflog show HEAD -n 20
git checkout -b recovered-branch <reflog-sha>

# 2. Clean interactive rebase of a branch diverged from base
git rebase --onto main <old-base> <feature-branch>

# 3. Verify DAG integrity and find dangling objects
git fsck --lost-found
```
