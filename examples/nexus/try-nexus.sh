#!/bin/sh
# Try the Nexus collector against a throwaway Nexus Community Edition in Docker, on this machine only.
#
#   sh try-nexus.sh            start Nexus, cache a few known-vulnerable packages through it, run the collector,
#                              then oss-intake, then the gate on what was cached since the first run
#   sh try-nexus.sh --remove   delete the container and its data
#
# Needs Docker, curl and python3; oss-intake for the last steps. Nexus listens on localhost only, on port 8081
# or NEXUS_PORT (NEXUS_PORT=8082 sh try-nexus.sh when 8081 is taken).
# Writes, next to where it is run: nexus-sboms/, nexus-state.json, nexus-report/, nexus-gate/ and
# nexus-recorded.json (the raw API answers, minus uploader IP addresses, for oss-intake's tests).
set -eu

NAME=oss-intake-nexus
PORT=${NEXUS_PORT:-8081}
URL=http://localhost:$PORT
HERE=$(cd "$(dirname "$0")" && pwd)

if [ "${1:-}" = "--remove" ]; then
    docker rm -f "$NAME" >/dev/null 2>&1 && echo "removed $NAME" || echo "$NAME was not running"
    exit 0
fi

if docker ps -a --format '{{.Names}}' | grep -qx "$NAME" \
        && ! docker port "$NAME" 8081/tcp 2>/dev/null | grep -q ":$PORT\$"; then
    docker rm -f "$NAME" >/dev/null  # left by a failed start, or made for another port
fi
if ! docker ps -a --format '{{.Names}}' | grep -qx "$NAME"; then
    if lsof -nP -iTCP:"$PORT" -sTCP:LISTEN >/dev/null 2>&1; then
        echo "Port $PORT is already in use by:"; lsof -nP -iTCP:"$PORT" -sTCP:LISTEN | tail -n +2
        echo "Run with another port, e.g.: NEXUS_PORT=$((PORT + 10000)) sh $0"; exit 1
    fi
    echo "== starting Nexus on port $PORT (first start takes 1 to 3 minutes)"
    docker run -d --name "$NAME" -p "127.0.0.1:$PORT:8081" sonatype/nexus3 >/dev/null
else
    docker start "$NAME" >/dev/null
fi
i=0
until curl -sf "$URL/service/rest/v1/status/writable" >/dev/null 2>&1; do
    i=$((i + 1)); [ "$i" -gt 60 ] && { echo "Nexus did not start in 5 minutes: docker logs $NAME"; exit 1; }
    sleep 5
done
echo "   Nexus is up"

PW=$(docker exec "$NAME" cat /nexus-data/admin.password 2>/dev/null || true)
if [ -z "$PW" ]; then
    if [ -z "${NEXUS_PASSWORD:-}" ]; then
        echo "The setup wizard replaced the initial admin password. Enter yours once, then run this again:"
        echo "  read -rs 'NEXUS_PASSWORD?Nexus admin password: '; echo; export NEXUS_PASSWORD   (zsh)"
        echo "  read -rs NEXUS_PASSWORD; export NEXUS_PASSWORD                                (bash)"
        exit 1
    fi
    PW=$NEXUS_PASSWORD
fi
AUTH="admin:$PW"

# Newer Community Edition releases need their licence accepted before use. That is your decision, so this
# script does not accept it for you: it stops, links the licence and gives the command that accepts it.
EULA=$(curl -s -u "$AUTH" "$URL/service/rest/v1/system/eula" || true)
case "$EULA" in
    *'"accepted" : false'*|*'"accepted":false'*)
        echo "Nexus Community Edition needs its licence accepted first. Read it:"
        echo "  https://links.sonatype.com/products/nxrm/ce-eula"
        echo "If you agree, accept it with this (it sends Nexus's own text back with accepted set to true):"
        echo "  curl -s -u \"admin:\$NEXUS_PASSWORD\" $URL/service/rest/v1/system/eula | python3 -c 'import json,sys; d=json.load(sys.stdin); d[\"accepted\"]=True; print(json.dumps(d))' | curl -s -u \"admin:\$NEXUS_PASSWORD\" -H 'Content-Type: application/json' -X POST --data @- $URL/service/rest/v1/system/eula"
        echo "(NEXUS_PASSWORD is your admin password; before the setup wizard has run, set it with:"
        echo "  export NEXUS_PASSWORD=\$(docker exec $NAME cat /nexus-data/admin.password) )"
        echo "then run this again."
        exit 1 ;;
esac

make_proxy() {  # format name remote
    if curl -sf -u "$AUTH" "$URL/service/rest/v1/repositories/$2" >/dev/null; then return; fi
    echo "== creating $2 (proxy of $3)"
    curl -sf -u "$AUTH" -H 'Content-Type: application/json' -X POST "$URL/service/rest/v1/repositories/$1/proxy" \
        -d "{\"name\":\"$2\",\"online\":true,\"storage\":{\"blobStoreName\":\"default\",\"strictContentTypeValidation\":true},
             \"proxy\":{\"remoteUrl\":\"$3\",\"contentMaxAge\":1440,\"metadataMaxAge\":1440},
             \"negativeCache\":{\"enabled\":true,\"timeToLive\":1440},
             \"httpClient\":{\"blocked\":false,\"autoBlock\":true}}" >/dev/null
}
make_proxy npm npm-proxy https://registry.npmjs.org
make_proxy pypi pypi-proxy https://pypi.org

fetch() {  # path, through the proxy, as a developer's npm or pip would
    code=$(curl -s -o /dev/null -w '%{http_code}' -u "$AUTH" "$URL/repository/$1")
    echo "   $code $1"
}
echo "== caching packages through the proxies"
fetch npm-proxy/lodash/-/lodash-4.17.15.tgz
fetch npm-proxy/minimist/-/minimist-1.2.0.tgz
fetch npm-proxy/@babel/traverse/-/traverse-7.22.0.tgz
fetch maven-central/org/apache/logging/log4j/log4j-core/2.14.1/log4j-core-2.14.1.jar
for pkg in django==2.2 urllib3==1.24.1; do
    python3 -m pip download -q --no-deps -d "$(mktemp -d)" \
        --index-url "http://admin:$PW@localhost:$PORT/repository/pypi-proxy/simple/" "$pkg" >/dev/null 2>&1 \
        && echo "   ok  pypi-proxy $pkg" || echo "   failed pypi-proxy $pkg"
done

echo "== recording the API answers (for oss-intake's tests)"
NEXUS_PASSWORD="$PW" python3 - "$URL" <<'PY'
import base64, json, os, sys, urllib.request
url = sys.argv[1]
auth = "Basic " + base64.b64encode(f"admin:{os.environ['NEXUS_PASSWORD']}".encode()).decode()
def get(path):
    req = urllib.request.Request(url + path, headers={"Authorization": auth, "Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=60) as r:
        return json.loads(r.read())
def scrub(o):
    if isinstance(o, dict):
        return {k: scrub(v) for k, v in o.items() if k not in ("uploaderIp",)}
    return [scrub(v) for v in o] if isinstance(o, list) else o
out = {"repositories": get("/service/rest/v1/repositories"), "components": {}}
for repo in ("npm-proxy", "pypi-proxy", "maven-central"):
    pages, token = [], None
    while True:
        pages.append(scrub(get(f"/service/rest/v1/components?repository={repo}"
                               + (f"&continuationToken={token}" if token else ""))))
        token = pages[-1].get("continuationToken")
        if not token:
            break
    out["components"][repo] = pages
json.dump(out, open("nexus-recorded.json", "w", encoding="utf-8"), indent=1)
print("   wrote nexus-recorded.json:", {r: sum(len(p.get("items") or []) for p in ps)
                                       for r, ps in out["components"].items()})
PY

echo "== collector, first run"
rm -rf nexus-sboms nexus-state.json
NEXUS_USERNAME=admin NEXUS_PASSWORD="$PW" python3 "$HERE/nexus_sbom.py" --url "$URL" --out nexus-sboms --state nexus-state.json

echo "== oss-intake on everything cached"
oss-intake --path nexus-sboms/all --out nexus-report --quiet --release-age-days 0 || true

echo "== a developer caches one more package; the gate checks only that"
fetch npm-proxy/axios/-/axios-0.21.0.tgz
NEXUS_USERNAME=admin NEXUS_PASSWORD="$PW" python3 "$HERE/nexus_sbom.py" --url "$URL" --out nexus-sboms --state nexus-state.json
if [ -n "$(ls nexus-sboms/new)" ]; then
    oss-intake --path nexus-sboms/new --out nexus-gate --quiet --fail-on malicious,recent \
        && echo "   gate: passed" || echo "   gate: exit $? (3 means it found something it is set to fail on)"
fi
echo "== done. Remove Nexus with: sh $0 --remove"
