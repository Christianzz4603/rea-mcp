# Security Policy

## Supported versions

Security fixes are applied to the latest code on the default branch. Deployments should rebuild regularly so they receive dependency and Ghidra updates.

## Reporting a vulnerability

Please do not publish exploitable details in a public issue. Contact the repository owner privately through GitHub's security advisory feature.

## Deployment guidance

- Set a strong, unique `MCP_API_KEY` in the hosting provider's secret manager.
- Never commit API keys, uploaded binaries, analysis databases, or local environment files.
- Keep the service behind HTTPS and use a persistent disk with restricted access.
- Limit upload size, analysis time, and concurrency.
- Only upload files you are authorized to analyze.
- Treat uploaded files as untrusted input. Ghidra parses files even though this service does not execute them.
- Before exposing the service to multiple users, add per-user identity, quotas, retention policies, and storage isolation.
