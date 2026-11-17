# REA MCP

**A hosted, Ghidra-backed remote MCP server for Claude and other MCP clients.**

REA MCP lets an AI assistant submit a binary to a remote service, have Ghidra analyze it, and then inspect the analysis through structured MCP tools. The service is designed for deployment as a Docker web service on Render.

> This repository is an independent project. It is not affiliated with or endorsed by the upstream REA project or the National Security Agency. Ghidra is a separate project maintained by the NSA.

## What it provides

- Remote MCP over **Streamable HTTP** at `/mcp`.
- Ghidra headless analysis for supported executable formats and processor architectures.
- Analysis reports persisted on a mounted data directory.
- Tools to analyze binaries, list functions, retrieve decompilation and assembly, inspect strings, and read binary metadata.
- API-key authentication compatible with Claude custom connector request headers.
- Docker and Render deployment configuration.
- Health endpoint at `/healthz` and a small service landing page at `/`.

## MCP tools

| Tool | Purpose |
| --- | --- |
| `analyze_binary` | Upload a Base64-encoded binary and run Ghidra headless analysis. Returns an analysis ID. |
| `list_analyses` | List analyses stored on this service. |
| `get_binary_info` | Get format, language, compiler, address range, and analysis counts. |
| `list_functions` | Search and page through discovered functions. |
| `decompile_function` | Retrieve Ghidra decompiler output for a function address or name. |
| `get_assembly` | Retrieve the captured instruction listing for a function. |
| `get_strings` | Search extracted strings. |

The first version intentionally provides **read-only static analysis**. It does not execute uploaded programs, attach to live processes, patch binaries, or run arbitrary shell commands.

## Deploy to Render

1. Push this repository to GitHub.
2. In Render, create a new **Blueprint** and select this repository. Render reads `render.yaml`.
3. Wait for the Docker build and deployment to finish.
4. Open the service's Environment settings and copy the generated `MCP_API_KEY` secret. Do not publish it.
5. Confirm `https://YOUR-SERVICE.onrender.com/healthz` returns JSON with `"ghidraAvailable": true`.
6. Your MCP endpoint is `https://YOUR-SERVICE.onrender.com/mcp`.

Ghidra is downloaded from the official NationalSecurityAgency/ghidra GitHub release during the Docker build. The Docker image uses the official release asset and verifies its published SHA-256 digest when GitHub provides one.

### Render sizing and storage

Ghidra is a substantial Java application. Use a service with enough memory for the binaries you intend to analyze; **4 GB RAM or more is a sensible starting point**, and large native libraries may need more. The Blueprint provisions a persistent disk at `/var/data`. Do not remove or change that mount unless you have moved analysis storage elsewhere.

The default upload limit is 64 MiB. Increase `MAX_UPLOAD_MB` only after checking your service's memory, request-size, and storage limits.

## Connect Claude

Claude's mobile app uses remote connectors that are configured from Claude's web settings. After adding the connector there, it can be enabled in the Android app.

1. Open Claude's web app and go to **Settings → Connectors** (or **Customize → Connectors**, depending on the current interface).
2. Choose **Add custom connector**.
3. Name it `REA MCP`.
4. Enter the remote MCP URL: `https://YOUR-SERVICE.onrender.com/mcp`.
5. Choose API-key / fixed-header authentication if Claude offers it.
6. Add this request header:
   - Header name: `Authorization`
   - Header value: `Bearer YOUR_MCP_API_KEY`
7. Save the connector, then open Claude on Android.
8. In a chat, use the **+ / tools / connectors** control and enable REA MCP.

If the connector setup offers a different authentication method, use the method that sends the same bearer token as an HTTP Authorization header. Never put the key in a prompt or commit it to this repository.

Claude's remote MCP requests come from Anthropic's cloud infrastructure, not directly from the phone. The service therefore needs a public HTTPS endpoint on the standard port 443.

## Local development

Requirements: Node.js 22+, npm, Java compatible with your installed Ghidra release, and a local Ghidra distribution.

```bash
npm install
cp .env.example .env
# Set GHIDRA_HOME to your local Ghidra directory.
npm run typecheck
npm test
npm run build
npm start
```

The local endpoint is `http://localhost:3000/mcp`. Set `MCP_API_KEY` in `.env` to enable authentication locally.

## Docker

```bash
docker build -t rea-mcp .
docker run --rm -p 3000:3000 \
  -e MCP_API_KEY='replace-with-a-long-random-secret' \
  -v rea-mcp-data:/var/data rea-mcp
```

## Configuration

| Variable | Default | Description |
| --- | --- | --- |
| `PORT` | `3000` | HTTP listen port. |
| `MCP_API_KEY` | unset | Bearer token. Required in production. |
| `GHIDRA_HOME` | `/opt/ghidra` in Docker | Ghidra installation directory. |
| `DATA_DIR` | `./data` | Persistent analysis storage directory. |
| `MAX_UPLOAD_MB` | `64` | Maximum decoded binary upload size. |
| `MAX_FUNCTIONS` | `2500` | Maximum functions recorded per analysis. |
| `MAX_DECOMPILES` | `250` | Maximum functions decompiled per analysis. |
| `MAX_STRINGS` | `10000` | Maximum strings recorded per analysis. |
| `MAX_INSTRUCTIONS_PER_FUNCTION` | `160` | Maximum assembly instructions captured per function. |
| `ANALYSIS_TIMEOUT_MS` | `900000` | Headless analysis timeout (15 minutes). |

## Important limitations

- This is an initial working foundation, not a replacement for the Ghidra desktop application.
- Decompilation is capped per analysis to bound runtime and report size. A function may be listed without a saved decompilation if it falls beyond the configured cap or Ghidra cannot decompile it.
- The service stores uploaded binaries and reports on its persistent disk. Treat uploads as sensitive and only submit files you are authorized to analyze.
- The server is designed for one service owner/API key. Do not share the key publicly. For a multi-user service, add per-user authentication, quotas, retention controls, and isolated storage before opening it to others.
- Uploaded binaries are never executed by this service. Ghidra parses them, so keep Ghidra updated and do not treat untrusted files as risk-free.

## License

This repository's code is released under the MIT License. Ghidra is a separate third-party dependency distributed under its own license. See [LICENSE](LICENSE).
