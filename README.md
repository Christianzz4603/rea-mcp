# REA MCP

**A hosted, Ghidra-backed remote MCP server for Claude and other MCP clients.**

REA MCP lets an AI assistant submit a binary to a remote service, have Ghidra analyze it, and inspect the saved static-analysis report through structured MCP tools.

> This is an independent project and is not affiliated with the upstream REA project or the National Security Agency. Ghidra is maintained separately by the NSA.

## MCP tools

### Analysis lifecycle
| Tool | Purpose |
| --- | --- |
| `analyze_binary` | Upload a Base64 binary and run Ghidra headless analysis. Returns an analysis ID. |
| `list_analyses` | List stored analyses and their status. |
| `get_binary_info` | Get format, language, compiler, address range, and analysis counts. |
| `get_analysis_overview` | Compact report dashboard with analysis coverage and available capabilities. |

### Functions and decompilation
| Tool | Purpose |
| --- | --- |
| `list_functions` | Browse discovered functions with pagination and optional name filtering. |
| `search_functions` | Search function names, signatures, and saved pseudocode. |
| `get_function_by_address` | Resolve an exact entry address to a function. |
| `get_function_summary` | Get a consolidated function card with pseudocode and bounded assembly. |
| `decompile_function` | Retrieve Ghidra decompiler pseudocode. |
| `get_assembly` | Retrieve captured assembly for a function. |
| `search_assembly` | Search captured assembly lines by mnemonic or text fragment. |
| `find_call_sites` | Find call-like instructions in captured assembly (bounded scan, not a complete call graph). |
| `compare_functions` | Retrieve two functions side-by-side for AI-assisted comparison. |

### Strings
| Tool | Purpose |
| --- | --- |
| `get_strings` | Browse/search extracted strings. |
| `find_strings` | Search extracted strings by case-insensitive substring with pagination. |

All analysis tools are read-only after import. Uploaded binaries are parsed by Ghidra and are never executed by this service. Assembly and call-site search are limited to instructions captured in the analysis report; they are not a substitute for a full live Ghidra query.

## Deploy to Render

1. Push this repository to GitHub.
2. In Render, create a new Blueprint and select this repository. Render reads `render.yaml`.
3. Wait for the Docker build and deployment.
4. Copy the generated `MCP_API_KEY` from the Render environment settings. Keep it private.
5. Confirm `https://YOUR-SERVICE.onrender.com/healthz` reports `"ghidraAvailable": true`.
6. The MCP endpoint is `https://YOUR-SERVICE.onrender.com/mcp`.

The Docker build downloads Ghidra from the official NSA GitHub releases. The service stores uploaded binaries and reports on the persistent disk mounted at `/var/data`. Ghidra is memory intensive; 4 GB RAM is a sensible starting point, with larger services recommended for large native libraries. The default upload limit is 64 MiB.

## Connect Claude

Configure a remote custom connector in Claude's web settings, then enable it in the Android app.

1. Open Claude web settings and navigate to Connectors.
2. Add a custom connector named `REA MCP`.
3. Set its URL to `https://YOUR-SERVICE.onrender.com/mcp`.
4. Configure bearer-token authentication using the header `Authorization: Bearer YOUR_MCP_API_KEY`.
5. Save, then enable REA MCP from Claude Android's tools/connectors control.

Claude's remote MCP requests originate from Anthropic's cloud infrastructure, so the service needs a public HTTPS endpoint. Never put the API key in a prompt or commit it to this repository.

## Local development

Requirements: Node.js 22+, npm, Java compatible with your Ghidra release, and a local Ghidra distribution.

```bash
npm install
cp .env.example .env
# Set GHIDRA_HOME to your local Ghidra directory.
npm run typecheck
npm test
npm run build
npm start
```

## Configuration

| Variable | Default | Description |
| --- | --- | --- |
| `PORT` | `3000` | HTTP listen port. |
| `MCP_API_KEY` | unset | Bearer token; required in production. |
| `GHIDRA_HOME` | `/opt/ghidra` in Docker | Ghidra installation directory. |
| `DATA_DIR` | `./data` | Persistent analysis storage. |
| `MAX_UPLOAD_MB` | `64` | Maximum decoded upload size. |
| `MAX_FUNCTIONS` | `2500` | Maximum functions recorded per analysis. |
| `MAX_DECOMPILES` | `250` | Maximum functions decompiled per analysis. |
| `MAX_STRINGS` | `10000` | Maximum strings recorded per analysis. |
| `MAX_INSTRUCTIONS_PER_FUNCTION` | `160` | Maximum assembly instructions captured per function. |
| `ANALYSIS_TIMEOUT_MS` | `900000` | Headless analysis timeout (15 minutes). |

## Security and limitations

- The service is intended for a single owner/API key. Add per-user authentication, quotas, retention controls, and isolated storage before offering public multi-user access.
- Uploaded binaries remain on persistent storage. Only upload files you are authorized to analyze.
- Ghidra parses untrusted input, so keep it updated and do not treat static parsing as risk-free.
- The current tools do not execute uploaded programs, attach to live processes, patch binaries, or run arbitrary shell commands.
- Decompilation is capped; a listed function may not have saved pseudocode if it is outside the configured cap or Ghidra cannot decompile it.

## License

MIT for this repository's code. Ghidra is a separate third-party dependency under its own license.
