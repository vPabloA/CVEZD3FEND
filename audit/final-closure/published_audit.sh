#!/usr/bin/env bash
set -euo pipefail
E=/tmp/published-evidence
mkdir -p "$E" data/dist
expected=661334a4e70d12c51ba627b35a795f39068ead0a
test "$(git rev-parse HEAD)" = "$expected"
test -z "$(git status --short)"
git rev-parse HEAD > "$E/head.txt"
git show --stat --oneline HEAD > "$E/commit-stat.txt"
git show acef9dd4932bd98e0cf49a3ee1f460c072aa553e:data/dist/knowledge-bundle.json > data/dist/knowledge-bundle.json
git show acef9dd4932bd98e0cf49a3ee1f460c072aa553e:data/dist/promoted-edges.json > data/dist/promoted-edges.json
git show acef9dd4932bd98e0cf49a3ee1f460c072aa553e:data/dist/quality-report.json > data/dist/quality-report.json
python3 -m compileall src tests 2>&1 | tee "$E/compileall.txt"
pytest -q 2>&1 | tee "$E/pytest.txt"
(cd web && npm run lint) 2>&1 | tee "$E/frontend-lint.txt"
(cd web && npm run test) 2>&1 | tee "$E/frontend-test.txt"
(cd web && npm run build) 2>&1 | tee "$E/frontend-build.txt"
git diff --check 2>&1 | tee "$E/diff-check.txt"
! grep -R "dangerouslySetInnerHTML" web/src
! grep -R "javascript:" web/src
! grep -R -E "(OPENAI_API_KEY|ANTHROPIC_API_KEY|sk-[A-Za-z0-9])" web/src
grep -n "focusedEdgeIds" web/src/components/reasoning/graph/graphAdapter.ts > "$E/trust-checks.txt"
grep -n "focusedRouteComplete" web/src/components/reasoning/graph/ThreatDefenseGraphNavigator.tsx >> "$E/trust-checks.txt"
grep -n "fallbackUsed" web/src/pages/AnalyzePage.tsx >> "$E/trust-checks.txt"
grep -n "reviewRequired: focusedRouteReviewRequired" web/src/pages/AnalyzePage.tsx >> "$E/trust-checks.txt"
git fetch origin audit/iteration2-preflight-20260618
git show origin/audit/iteration2-preflight-20260618:audit/iteration2_demo.py > /tmp/iteration2_demo.py
python /tmp/iteration2_demo.py 2>&1 | tee "$E/real-demo.txt"
cp iteration2-real-*.json "$E"/
CVEzD3FEND api > "$E/api.log" 2>&1 & api_pid=$!
(cd web && npm run dev -- --host 127.0.0.1 --port 5173 > "$E/vite.log" 2>&1) & vite_pid=$!
trap 'kill "$api_pid" "$vite_pid" 2>/dev/null || true' EXIT
for i in $(seq 1 60); do
  curl -fsS http://127.0.0.1:8000/api/health >/dev/null && curl -fsS http://127.0.0.1:5173/ >/dev/null && break
  sleep 1
done
curl -fsS http://127.0.0.1:8000/api/health > "$E/health.json"
git show origin/audit/iteration2-preflight-20260618:audit/final-closure/capture.py > /tmp/capture.py
python /tmp/capture.py
find web/docs/screenshots -maxdepth 1 -name 'multi-cve-0[347]-*.png' -printf '%f %s bytes\n' | sort > "$E/screenshots.txt"
awk '$2 < 5000 { exit 1 }' "$E/screenshots.txt"
kill "$api_pid" "$vite_pid" 2>/dev/null || true
trap - EXIT
