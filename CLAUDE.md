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
- No secrets in code or git — use REPLACE_ME placeholders
- Conventional commits: `type(scope): description`
