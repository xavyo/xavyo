# Install Graphify for a project

Use this path for a repository expected to be long-lived and multi-component, or
when architecture and blast-radius questions will recur. Skip it for small, local
projects. Obtain approval before installing software or changing project files.

## Install the CLI once per workstation

Graphify requires Python 3.10 or later. Install its official package with `uv`:

```bash
uv tool install graphifyy
```

The supported alternative is `pipx install graphifyy`. The PyPI package has two
`y` characters; the command is `graphify`. If the command is not found after a
`uv` installation, run `uv tool update-shell` and reopen the terminal.

## Register it in the target repository

Run from the repository root:

```bash
graphify install --project --platform agents
graphify install --project --platform claude
```

The first command installs the generic Agent Skill under `.agents/skills` for
Codex and compatible agents. The second installs the Claude project integration,
which is also read by Grok Build. On Windows, replace `claude` with `windows`.

Inspect the generated diff before committing it. Depending on the platform,
Graphify can add skill files, update `CLAUDE.md`, and create `.claude/settings.json`
for its hooks. Do not use strict mode unless the user explicitly asks for it.

## Build and maintain the graph

Build the initial graph from the coding agent:

- Codex: `$graphify .`
- Claude Code and Grok Build: `/graphify .`

Use the same command with `--update` after meaningful architecture changes. Add
`graphify-out/` to `.gitignore` unless the team explicitly chooses to version the
generated graph.

Use Graphify for multi-hop navigation and blast-radius exploration. Verify
important inferred edges in source code; a graph is not completion evidence.

## Optional: MCP server

The steps above install the CLI and the `$graphify` / `/graphify` skill, which is
enough for map generation and navigation. Add the MCP server only when you want the
agent to query the graph through repeated tool calls (`query_graph`, `get_node`,
`get_neighbors`, `shortest_path`, `graph_stats`, and the PR-impact tools) rather
than the skill alone. It stays optional; do not make it a prerequisite for using
Graphify.

The base package does **not** include the MCP dependency, so `python -m
graphify.serve` fails with `ModuleNotFoundError: mcp` until the `mcp` extra is
installed. Install it into the same tool environment as the CLI:

```bash
uv tool install "graphifyy[mcp]"          # fresh install
uv tool install --with mcp graphifyy --reinstall   # add to an existing install
```

The supported alternative is `pipx install "graphifyy[mcp]"`. Installing a bare
`mcp` with `pip` lands in a different environment than the `uv`/`pipx` tool venv and
does not fix the import, so always add the extra to the tool itself.

Build the graph first so `graphify-out/graph.json` exists, then run the stdio
server:

```bash
python -m graphify.serve graphify-out/graph.json
```

Register that command as an stdio MCP server through your agent's own MCP
mechanism. For Codex, add it to `~/.codex/config.toml` (and keep
`multi_agent = true` under `[features]`):

```toml
[mcp_servers.graphify]
command = "python"
args = ["-m", "graphify.serve", "graphify-out/graph.json"]
```

For Claude Code or Cursor, add the same command to the project `.mcp.json`:

```json
{
  "mcpServers": {
    "graphify": {
      "command": "python",
      "args": ["-m", "graphify.serve", "graphify-out/graph.json"]
    }
  }
}
```

Then confirm the integration actually starts instead of failing silently: check
that `python -c "import mcp"` resolves in the tool environment, launch the server
against the built graph and confirm it does not exit with the `mcp` import error,
and from the agent call a read-only tool such as `graph_stats` and verify it
returns. A registered-but-broken MCP server drops a whole category of tools with no
error in the agent, so treat the `graph_stats` round-trip as the real check.

Source: [official Graphify installation guide](https://github.com/Graphify-Labs/graphify#install).
