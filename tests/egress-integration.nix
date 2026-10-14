# Multi-node integration test for the egress proxy (proxy/). The Go unit tests
# cover its logic in-process; this covers what they cannot — the real binary as
# a systemd service, reached over a network by a separate client, and chaining
# through an upstream "corporate" proxy. That chaining path had been only
# manually verifiable (no corporate proxy to point at in CI); here a second
# instance of our own proxy in log mode *is* the corporate proxy, and its audit
# log is the proof the traffic chained rather than dialing out directly.
#
# What the launcher does to the QEMU command line (restrict=on + guestfwd) is
# still out of reach — a nixosTest drives its own QEMU — so that hop stays a
# manual host check. Everything from the proxy inward is covered here.
#
# Topology:   client ──proxy(enforce)──corp(log, permissive)──upstream
# The proxy's HTTP(S)_PROXY points at corp, so every upstream dial — the opaque
# CONNECT leg and the reverse-proxy leg both — goes through it.
{ pkgs, lib, egressProxy }:

let
  # Records the credential headers it receives, so the test can prove the
  # proxy stripped the client's planted key and injected the host-held one.
  echoServer = pkgs.writeText "echo-server.py" ''
    import http.server, socketserver
    class H(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            with open("/tmp/seen", "a") as f:
                f.write("%s x-api-key=%s authorization=%s\n" % (
                    self.path,
                    self.headers.get("x-api-key"),
                    self.headers.get("authorization")))
            self.send_response(200); self.end_headers(); self.wfile.write(b"ok")
        def log_message(self, *a): pass
    socketserver.TCPServer.allow_reuse_address = True
    socketserver.TCPServer(("", 80), H).serve_forever()
  '';

  proxyCfg = pkgs.writeText "proxy.json" (builtins.toJSON {
    listen = "0.0.0.0:3128";
    mode = "enforce";
    allowlistFile = "/etc/egress-allow.txt";
    auditLog = "/tmp/proxy-audit.jsonl";
    endpoints = [{
      prefix = "/anthropic";
      upstream = "http://upstream";
      keyEnv = "ANTHROPIC_API_KEY";
      header = "x-api-key";
      allowedPaths = [ "/v1/messages" ];
    }];
  });

  # The "corporate" upstream proxy: our binary, log mode so it forwards
  # everything (and records would_deny), no endpoints — a plain CONNECT +
  # absolute-form forward proxy.
  corpCfg = pkgs.writeText "corp.json" (builtins.toJSON {
    listen = "0.0.0.0:3129";
    mode = "log";
    allowlistFile = "/etc/egress-allow.txt";
    auditLog = "/tmp/corp-audit.jsonl";
    endpoints = [ ];
  });

  proxyService = exec: env: {
    wantedBy = [ "multi-user.target" ];
    after = [ "network-online.target" ];
    wants = [ "network-online.target" ];
    environment = env;
    serviceConfig = { ExecStart = exec; Restart = "no"; };
  };
in
pkgs.testers.runNixOSTest {
  name = "egress-integration";

  # A normal run takes well under a minute locally and ~2.5 in CI. The default
  # hour only matters when a VM stalls before boot: the driver waits on its
  # monitor/shell sockets with no timeout, so a stuck QEMU would hold the job
  # for the full hour instead of failing fast.
  globalTimeout = 600;

  nodes = {
    upstream = { ... }: {
      networking.firewall.enable = false;
      systemd.services.echo = {
        wantedBy = [ "multi-user.target" ];
        after = [ "network.target" ];
        serviceConfig.ExecStart = "${pkgs.python3}/bin/python3 ${echoServer}";
      };
    };

    corp = { ... }: {
      networking.firewall.enable = false;
      environment.etc."egress-allow.txt".text = ""; # log mode forwards regardless
      systemd.services.corp = proxyService "${egressProxy}/bin/egress-proxy -config ${corpCfg}" { };
    };

    proxy = { ... }: {
      networking.firewall.enable = false;
      # Bare 'upstream' grants :80 only; :443 is denied, which also exercises
      # the per-entry port grant.
      environment.etc."egress-allow.txt".text = "upstream:80\n";
      systemd.services.egress = proxyService
        "${egressProxy}/bin/egress-proxy -config ${proxyCfg}"
        {
          HTTP_PROXY = "http://corp:3129";
          HTTPS_PROXY = "http://corp:3129";
          ANTHROPIC_API_KEY = "host-held-key";
        };
    };

    client = { ... }: {
      networking.firewall.enable = false;
      environment.systemPackages = [ pkgs.curl ];
    };
  };

  testScript = ''
    start_all()
    upstream.wait_for_unit("echo.service")
    upstream.wait_for_open_port(80)
    corp.wait_for_unit("corp.service")
    corp.wait_for_open_port(3129)
    proxy.wait_for_unit("egress.service")
    proxy.wait_for_open_port(3128)
    client.wait_for_unit("multi-user.target")

    # --- reverse-proxy leg: allowed path reaches upstream; planted credential
    #     is stripped and the host-held key injected ---
    code = client.succeed(
        "curl -s -o /dev/null -w '%{http_code}' -H 'x-api-key: attacker-planted' "
        "http://proxy:3128/anthropic/v1/messages"
    )
    assert code == "200", f"allowed endpoint path returned {code}, want 200"

    seen = upstream.succeed("cat /tmp/seen")
    assert "/v1/messages x-api-key=host-held-key" in seen, \
        f"upstream did not see the injected key: {seen!r}"
    assert "attacker-planted" not in seen, \
        f"planted credential was not stripped: {seen!r}"

    # --- reverse-proxy leg: denied path is refused by the proxy, never reaches
    #     upstream ---
    code = client.succeed(
        "curl -s -o /dev/null -w '%{http_code}' http://proxy:3128/anthropic/v1/files"
    )
    assert code == "403", f"denied endpoint path returned {code}, want 403"
    assert "/v1/files" not in upstream.succeed("cat /tmp/seen"), \
        "denied path leaked to upstream"

    # --- CONNECT leg: allowed host:port tunnels; the off-list port is denied ---
    # curl exits non-zero on both (TLS fails over the plain tunnel; 403 on the
    # denied port), and the test driver runs under pipefail — so capture to a
    # file and let grep, not curl's exit, decide.
    client.succeed(
        "curl -sv -x http://proxy:3128 https://upstream:80/ >/tmp/ok.log 2>&1 || true; "
        "grep -qiE 'connection established|replied 200 to connect' /tmp/ok.log"
    )
    client.succeed(
        "curl -sv -x http://proxy:3128 https://upstream/ >/tmp/deny.log 2>&1 || true; "
        "grep -q '403' /tmp/deny.log"
    )

    # --- chaining: every upstream dial went through corp, so corp's audit log
    #     holds both legs. This is the corporate-upstream-proxy path, verified
    #     without a real corporate proxy. ---
    corp_audit = corp.succeed("cat /tmp/corp-audit.jsonl")
    assert '"kind":"http"' in corp_audit and '"host":"upstream"' in corp_audit, \
        f"reverse-proxy leg did not chain through corp: {corp_audit!r}"
    assert '"kind":"connect"' in corp_audit and '"port":80' in corp_audit, \
        f"CONNECT leg did not chain through corp: {corp_audit!r}"

    # --- the proxy's own audit log recorded the enforce decisions ---
    proxy_audit = proxy.succeed("cat /tmp/proxy-audit.jsonl")
    assert '"path":"/v1/files","decision":"deny"' in proxy_audit, \
        f"proxy did not record the path denial: {proxy_audit!r}"
    assert '"port":443,"path":"","decision":"deny"' in proxy_audit, \
        f"proxy did not record the off-port CONNECT denial: {proxy_audit!r}"
  '';
}
