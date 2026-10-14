# Drives egress-report (scripts/egress-report.sh, packaged in flake.nix)
# against a synthesized capture: DNS query/answer, a TLS ClientHello with
# SNI, and raw TCP/UDP flows with no hostname. Covers the summarize
# sections, allowlist matching (subdomain + "*." and ":port" tolerance,
# exit 2 on violations), and follow mode's live alert lines.
{ pkgs, lib, egressReport }:

pkgs.runCommand "egress-report-test"
  {
    nativeBuildInputs = [ egressReport pkgs.python3 ];
  } ''
    set -euo pipefail
    export HOME="$TMPDIR"  # tshark wants somewhere for its config state

    python3 ${./make-egress-pcap.py} session.pcap

    echo "--- summarize, no allowlist"
    egress-report summarize session.pcap | tee report.txt
    grep -q 'api\.anthropic\.com' report.txt
    grep -q 'evil\.example\.com' report.txt
    grep -q '203\.0\.113\.7:4444' report.txt
    grep -q '203\.0\.113\.9:123' report.txt
    # The address the DNS answer named must be attributed, not "no hostname".
    if grep -q '198\.51\.100\.10:443' report.txt; then
      echo "FAIL: DNS-attributed destination listed as having no hostname" >&2
      exit 1
    fi
    if grep -q 'allowlist violations' report.txt; then
      echo "FAIL: violations section printed without an allowlist" >&2
      exit 1
    fi
    # IPv6: AAAA answers attribute v6 flows; unknown ones print as [addr]:port.
    grep -q 'v6\.example\.net' report.txt
    grep -qF '[2001:db8::bad]:443' report.txt
    if grep -q '2001:db8::10' report.txt; then
      echo "FAIL: AAAA-attributed v6 destination listed as having no hostname" >&2
      exit 1
    fi
    # Inbound replies and resolver meta-traffic count nothing.
    if grep -q '10\.0\.2\.15' report.txt; then
      echo "FAIL: inbound reply to the guest counted as a destination" >&2
      exit 1
    fi
    if grep -q 'claude-vm' report.txt; then
      echo "FAIL: single-label hostname lookup counted as an egress domain" >&2
      exit 1
    fi

    cat > allow.txt <<'EOF'
    # exercises comment stripping, "*." and ":port" tolerance
    *.anthropic.com:443
    pool.ntp.org
    EOF

    echo "--- summarize with allowlist (expect exit 2)"
    rc=0
    egress-report summarize session.pcap --allowlist allow.txt > report2.txt || rc=$?
    cat report2.txt
    [ "$rc" -eq 2 ]
    grep -A2 'allowlist violations:' report2.txt | grep -q 'evil\.example\.com'
    if grep -A2 'allowlist violations:' report2.txt | grep -q 'api\.anthropic\.com'; then
      echo "FAIL: allowlisted domain reported as a violation" >&2
      exit 1
    fi

    echo "--- follow mode"
    egress-report follow session.pcap --allowlist allow.txt --alerts alerts.log &
    follow_pid=$!
    for _ in $(seq 1 100); do
      grep -q 'evil\.example\.com' alerts.log 2>/dev/null && break
      sleep 0.2
    done
    kill "$follow_pid" 2>/dev/null || true
    grep -q 'egress-alert: evil\.example\.com' alerts.log
    if grep -q 'api\.anthropic\.com' alerts.log; then
      echo "FAIL: follow mode alerted on an allowlisted domain" >&2
      exit 1
    fi

    touch $out
  ''
