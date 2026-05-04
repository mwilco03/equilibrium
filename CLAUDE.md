# equilibrium

## Shared Memory

This project lives on a shared Ceph mount at `/mnt/cephfs/shared/projects/equilibrium/`. Multiple Proxmox nodes can run Claude Code against it. To keep memory consistent across nodes, Claude Code's auto-memory directory should be a symlink pointing to `.claude-memory/` inside the project directory on the Ceph share — not stored locally under `/root/.claude/projects/`.

If the symlink doesn't exist yet, set it up:

```bash
# Derive the Claude Code project path (slashes become dashes)
PROJECT_PATH="/mnt/cephfs/shared/projects/equilibrium"
CLAUDE_PROJECT_DIR="/root/.claude/projects/$(echo "$PROJECT_PATH" | sed 's|/|-|g; s|^-||')"

# Ensure the shared memory dir exists
mkdir -p "$PROJECT_PATH/.claude-memory"

# Ensure the Claude Code project dir exists
mkdir -p "$CLAUDE_PROJECT_DIR"

# Replace local memory with symlink to Ceph
rm -rf "$CLAUDE_PROJECT_DIR/memory"
ln -s "$PROJECT_PATH/.claude-memory" "$CLAUDE_PROJECT_DIR/memory"
```

Always verify the symlink is in place before writing memories. This ensures any node (trouble, mayhem, chaos, etc.) sees the same project memory.

## Commands

```bash
# Build & test commands go here
```

## Rules

- Constants over literals, enums over hardcodes
- No secrets in code or git, use REPLACE_ME placeholders
- Conventional commits: `type(scope): description`

## CI economy

GitHub Actions minutes are a finite resource on this project. Be judicious:

- **Batch commits before pushing.** Multiple related edits in one push is one Pages build; the same edits across N pushes is N builds.
- **Run validation locally** before pushing data or schema changes:
  - `cd spa && pnpm run typecheck && pnpm run build`
  - `node .github/scripts/check-dc-refs.mjs`
  - ajv schema validation against every `data/techniques/*.json`
- **Doc-only changes do not need to wait for CI**: `docs/**`, `README.md`, and `CLAUDE.md` are excluded from Pages and Validate triggers via `paths-ignore` / `paths` filters.
- The `Validate` workflow uses concurrency cancellation; a new commit on the same ref pre-empts the in-flight run, but stacking many pushes still wastes start-up overhead.
