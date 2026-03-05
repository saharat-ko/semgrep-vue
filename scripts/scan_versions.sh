#!/bin/bash
# scan_versions.sh
# Scan Vue.js แต่ละ version ด้วย Semgrep
# - SAST: scan เฉพาะ source code (.ts/.js/.vue) ไม่รวม test files
# - SCA:  semgrep ci สำหรับ Supply Chain / CVE

set -e

REPO_DIR="$(pwd)/core"
RESULTS_DIR="$(pwd)/results"

# =============================================
# แก้ตรงนี้! ใส่ versions ที่ตัวเองรับผิดชอบ
# คน 1: "v3.0.0" "v3.0.8" "v3.0.6" "v3.0.4"
# คน 2: "v3.1.0" "v3.1.5" "v3.1.3" "v3.1.2"
# คน 3: "v3.2.0" "v3.2.42" "v3.2.46" "v3.2.34"
# คน 4: "v3.3.0" "v3.3.9" "v3.3.5" "v3.3.7"
# คน 5: "v3.4.0" "v3.4.28" "v3.4.22" "v3.4.32"
# คน 6: "v3.5.0" "v3.5.14" "v3.5.15" "v3.5.13"
# =============================================
VERSIONS=("v3.0.0")

mkdir -p "$RESULTS_DIR"

# -----------------------------------------------
# Clone vuejs/core ถ้ายังไม่มี
# -----------------------------------------------
if [ ! -d "$REPO_DIR" ]; then
  echo "Cloning vuejs/core..."
  git clone https://github.com/vuejs/core.git --no-single-branch core
fi

echo "Fetching tags..."
cd "$REPO_DIR"
git fetch --tags

echo "Available tags:"
git tag -l "v3.*" | grep -E "^v3\.[0-9]+\.[0-9]+$" | sort -V | tail -5

TOTAL=${#VERSIONS[@]}
COUNT=0

for VERSION in "${VERSIONS[@]}"; do
  COUNT=$((COUNT + 1))
  echo ""
  echo "==============================="
  echo "[$COUNT/$TOTAL] Scanning $VERSION..."
  echo "==============================="

  git checkout "tags/$VERSION" -f 2>/dev/null || {
    echo "Tag $VERSION not found, skipping..."
    continue
  }

  # -----------------------------------------------
  # SAST Scan (source code เท่านั้น)
  # -----------------------------------------------
  SAST_FILE="$RESULTS_DIR/${VERSION}_sast.json"

  semgrep scan \
    --config "p/default" \
    --config "p/javascript" \
    --config "p/typescript" \
    --config "p/security-audit" \
    --config "p/owasp-top-ten" \
    --exclude="*__tests__*" \
    --exclude="*__mocks__*" \
    --exclude="*examples*" \
    --exclude="*size-check*" \
    --exclude="*template-explorer*" \
    --exclude="*runtime-test*" \
    --include="*.ts" \
    --include="*.js" \
    --include="*.vue" \
    --json \
    --output "$SAST_FILE" \
    . || true

  SAST_COUNT=$(python3 -c "
import json
try:
    d = json.load(open('$SAST_FILE'))
    print(len(d.get('results', [])))
except:
    print('?')
")
  echo "SAST: $VERSION -> $SAST_COUNT findings"

  # -----------------------------------------------
  # Supply Chain Scan (SCA) หา CVE
  # -----------------------------------------------
  SCA_FILE="$RESULTS_DIR/${VERSION}_sca.json"

  semgrep ci \
    --supply-chain \
    --exclude="*__tests__*" \
    --exclude="*__mocks__*" \
    --exclude="*examples*" \
    --exclude="*size-check*" \
    --exclude="*template-explorer*" \
    --exclude="*runtime-test*" \
    --json \
    --output "$SCA_FILE" || true

  SCA_COUNT=$(python3 -c "
import json
try:
    d = json.load(open('$SCA_FILE'))
    results = d.get('results', [])
    cve_list = [r.get('extra',{}).get('metadata',{}).get('cve','') for r in results if r.get('extra',{}).get('metadata',{}).get('cve','')]
    print(f'total={len(results)} cve={len(cve_list)}')
except:
    print('?')
")
  echo "SCA:  $VERSION -> $SCA_COUNT"

done

echo ""
echo "==============================="
echo "Scan complete! Summary:"
echo "==============================="
python3 -c "
import json, glob, os

print(f\"{'Version':<12} {'SAST':>6} {'SCA Total':>10} {'CVEs':>6}\")
print('-' * 38)

versions = set()
for f in glob.glob('$RESULTS_DIR/v*_sast.json'):
    versions.add(os.path.basename(f).replace('_sast.json',''))

for version in sorted(versions):
    sast, sca_total, cve = '?', '?', '?'
    try:
        d = json.load(open(f'$RESULTS_DIR/{version}_sast.json'))
        sast = len(d.get('results', []))
    except: pass
    try:
        d = json.load(open(f'$RESULTS_DIR/{version}_sca.json'))
        results = d.get('results', [])
        cve_list = [r.get('extra',{}).get('metadata',{}).get('cve','') for r in results if r.get('extra',{}).get('metadata',{}).get('cve','')]
        sca_total = len(results)
        cve = len(cve_list)
    except: pass
    print(f'{version:<12} {str(sast):>6} {str(sca_total):>10} {str(cve):>6}')
"