#!/usr/bin/env bash
set -euo pipefail
E=/tmp/pr6-evidence
mkdir -p "$E" data/dist
expected=7f96d3c8f899a54705e040db69f276d55686eda0
test "$(git rev-parse HEAD)" = "$expected"
test -z "$(git status --short)"
git rev-parse HEAD > "$E/head.txt"
git show --stat --oneline HEAD > "$E/head-stat.txt"
git diff --stat origin/main...HEAD > "$E/diff-stat.txt"
git show acef9dd4932bd98e0cf49a3ee1f460c072aa553e:data/dist/knowledge-bundle.json > data/dist/knowledge-bundle.json
git show acef9dd4932bd98e0cf49a3ee1f460c072aa553e:data/dist/promoted-edges.json > data/dist/promoted-edges.json
git show acef9dd4932bd98e0cf49a3ee1f460c072aa553e:data/dist/quality-report.json > data/dist/quality-report.json
python3 -m compileall src tests 2>&1 | tee "$E/compileall.txt"
pytest -q 2>&1 | tee "$E/pytest.txt"
(cd web && npm run lint) 2>&1 | tee "$E/frontend-lint.txt"
(cd web && npm run test) 2>&1 | tee "$E/frontend-test.txt"
(cd web && npm run build) 2>&1 | tee "$E/frontend-build.txt"
git diff --check origin/main...HEAD 2>&1 | tee "$E/diff-check.txt"
