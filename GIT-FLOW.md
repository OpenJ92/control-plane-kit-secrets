# Git Flow

Use short-lived branches with the `codex/` prefix for implementation work.

```bash
git checkout -b codex/<issue>-short-description
```

Open pull requests against `main` for this standalone repository unless an
issue explicitly names another base branch. Keep PRs scoped to one issue or one
coherent child issue.

Before opening a PR, run:

```bash
git diff --check
./test.sh
```

Do not merge work that weakens the package boundary, leaks secret material, or
adds secret persistence/API behavior before its owning issue opens.
