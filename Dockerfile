FROM eclipse-temurin:25-jre-noble

ENV DEBIAN_FRONTEND=noninteractive
ENV GHIDRA_HOME=/opt/ghidra
ENV DATA_DIR=/var/data
ENV PORT=3000

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl python3 unzip tini \
    && rm -rf /var/lib/apt/lists/*

# Resolve the official release asset and its digest from the GitHub release API.
# The asset is downloaded from NationalSecurityAgency/ghidra, never from a mirror.
RUN python3 - <<'PY'
import hashlib
import json
import os
import pathlib
import subprocess
import urllib.request

tag = os.environ.get("GHIDRA_RELEASE_TAG", "Ghidra_12.2_build")
api = f"https://api.github.com/repos/NationalSecurityAgency/ghidra/releases/tags/{tag}"
request = urllib.request.Request(api, headers={"Accept": "application/vnd.github+json", "User-Agent": "rea-mcp-build"})
with urllib.request.urlopen(request, timeout=30) as response:
    release = json.load(response)

assets = [a for a in release.get("assets", []) if a["name"].lower().endswith(".zip") and a["name"].lower().startswith("ghidra_") and "source" not in a["name"].lower()]
if not assets:
    raise SystemExit(f"No official Ghidra distribution ZIP found for {tag}")
asset = max(assets, key=lambda a: a.get("size", 0))
archive = pathlib.Path("/tmp/ghidra.zip")
urllib.request.urlretrieve(asset["browser_download_url"], archive)
digest = asset.get("digest")
if digest and digest.startswith("sha256:"):
    actual = hashlib.sha256(archive.read_bytes()).hexdigest()
    expected = digest.split(":", 1)[1]
    if actual != expected:
        raise SystemExit(f"Ghidra SHA-256 mismatch: expected {expected}, got {actual}")
subprocess.run(["unzip", "-q", str(archive), "-d", "/opt"], check=True)
install = pathlib.Path("/opt") / asset["name"].removesuffix(".zip")
if not install.exists():
    candidates = [p for p in pathlib.Path("/opt").glob("ghidra_*") if p.is_dir()]
    if len(candidates) != 1:
        raise SystemExit("Could not uniquely identify extracted Ghidra directory")
    install = candidates[0]
install.rename("/opt/ghidra")
archive.unlink(missing_ok=True)
print(f"Installed {asset['name']} ({asset['size']} bytes)")
PY

WORKDIR /app
COPY package*.json ./
RUN npm install --omit=dev
COPY tsconfig.json ./
COPY src ./src
COPY ghidra_scripts ./ghidra_scripts
COPY public ./public
RUN npm install --include=dev && npm run build && npm prune --omit=dev

RUN mkdir -p /var/data && chown -R 10001:10001 /var/data /app /opt/ghidra
USER 10001
EXPOSE 3000
ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["node", "dist/index.js"]
