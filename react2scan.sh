#!/bin/bash
#
# http://www.rootandbeer.com
# http://www.github.com/rootandbeer
#

DEFAULT_PORT=8443
PORT="$DEFAULT_PORT"
TARGET_INPUT=""

# Parse flags
while [[ $# -gt 0 ]]; do
    case "$1" in
        -p|--port)
            PORT="$2"
            shift 2
            ;;
        *)
            TARGET_INPUT="$1"
            shift
            ;;
    esac
done

echo "[*] React2Shell Detection Probe (CVE‑2025‑55182 / CVE‑2025‑66478)"
echo ""
echo "[*] Port: $PORT"
echo ""

BOUNDARY="----WebKitFormBoundaryx8jO2oVc6SWP3Sad"

BODY=$(cat <<EOF
--${BOUNDARY}
Content-Disposition: form-data; name="1"

{}
--${BOUNDARY}
Content-Disposition: form-data; name="0"

["\$1:a:a"]
--${BOUNDARY}--
EOF
)

#############################################
# Scanner
#############################################
scan_target() {
    local URL="$1"
    echo "[*] Target: $URL"

    RESPONSE=$(curl -s --max-time 3 -w "\n%{http_code}" \
        -X POST "$URL" \
        -H "Next-Action: x" \
        -H "Content-Type: multipart/form-data; boundary=${BOUNDARY}" \
        --data-binary "${BODY}" \
        2>&1)

    HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
    BODY_RESPONSE=$(echo "$RESPONSE" | sed '$d')

    if [[ "${HTTP_CODE}" == "500" ]] && echo "${BODY_RESPONSE}" | grep -q 'E{"digest"'; then
        echo "[!] VULNERABLE"
    elif [[ "${HTTP_CODE}" == "500" ]]; then
        echo "[?] UNKNOWN 500"
    else
        echo "[+] Not vulnerable (HTTP ${HTTP_CODE})"
    fi

    echo ""
}

#############################################
# Subnet expansion without nmap
#############################################
expand_cidr() {
    local cidr="$1"
    local ip=$(echo "$cidr" | cut -d/ -f1)
    local mask=$(echo "$cidr" | cut -d/ -f2)

    IFS='.' read -r i1 i2 i3 i4 <<< "$ip"

    if [[ "$mask" != "24" ]]; then
        echo "[-] Only /24 CIDR supported in this simple expander"
        exit 1
    fi

    for last in $(seq 1 254); do
        echo "$i1.$i2.$i3.$last"
    done
}

expand_range() {
    local range="$1"
    local base=$(echo "$range" | cut -d. -f1-3)
    local start=$(echo "$range" | awk -F. '{print $4}' | cut -d- -f1)
    local end=$(echo "$range" | awk -F. '{print $4}' | cut -d- -f2)

    for i in $(seq "$start" "$end"); do
        echo "$base.$i"
    done
}

#############################################
# Input routing
#############################################

if [[ -z "$TARGET_INPUT" ]]; then
    echo "Usage:"
    echo "  $0 host"
    echo "  $0 192.168.1.0/24"
    echo "  $0 192.168.1.10-50"
    echo "  $0 ips.txt"
    echo "  Optional: -p <port>"
    exit 1
fi

if [[ -f "$TARGET_INPUT" ]]; then
    echo "[*] Loading from file"
    while read -r ip; do
        [[ -z "$ip" ]] && continue
        scan_target "http://$ip:$PORT"
    done < "$TARGET_INPUT"

elif [[ "$TARGET_INPUT" =~ ^([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)/24$ ]]; then
    echo "[*] Expanding CIDR $TARGET_INPUT"
    for ip in $(expand_cidr "$TARGET_INPUT"); do
        scan_target "http://$ip:$PORT"
    done

elif [[ "$TARGET_INPUT" =~ - ]]; then
    echo "[*] Expanding range $TARGET_INPUT"
    for ip in $(expand_range "$TARGET_INPUT"); do
        scan_target "http://$ip:$PORT"
    done

else
    echo "[*] Scanning single host"
    scan_target "http://$TARGET_INPUT:$PORT"
fi
