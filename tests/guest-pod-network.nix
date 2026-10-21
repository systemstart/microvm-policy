# The guest module (modules/egress.nix) without QEMU's user-mode netdev: the
# shape of a VM whose platform owns the hypervisor, e.g. KubeVirt on a pod
# network. There is no restrict=on and no guestfwd; the seal is a network
# policy outside the guest, the policy file arrives as instance data (a unit
# writes it, as cloud-init's write_files would), the resolver is the
# platform's (DHCP), and nobody writes HTTP(S)_PROXY into a session.
#
# The network policy is emulated with nftables on the guest's OUTPUT hook
# (default drop, only the proxy's address:port and replies allowed): what a
# default-deny Cilium policy does to a pod, minus everything Cilium itself
# might get wrong — this test proves the guest side, not the platform's
# policy engine.
#
# Asserted:
#   - egress-seal reads the policy written by the instance-data unit (ordered
#     after it via stateAfter), verifies the seal and empties resolv.conf;
#     its positive control reached the proxy (audit: egress-seal.invalid);
#   - the seal self-test FAILS the unit on an unsealed guest (node
#     `unsealed`: same config, no nftables) and is INCONCLUSIVE — also a
#     failed unit — when the proxy does not answer (node `noproxy`);
#   - with no EGRESS_PROXY_ADDR in that file, egress.proxyAddress is the
#     fallback, and proxyEnvironment exports HTTP(S)_PROXY/NO_PROXY to the
#     manager environment (a later service) and to login shells;
#   - through that environment, with no proxy flag: an allowlisted host is
#     reached, an off-list one is refused by the proxy (403) and audited as
#     deny; direct egress past the proxy is refused;
#   - the ssh wrapper takes the same fallback address (CONNECT to :22 shows
#     up in the proxy's audit log).
{ pkgs, lib, egressProxy }:

let
  proxyCfg = pkgs.writeText "proxy.json" (builtins.toJSON {
    listen = "0.0.0.0:3128";
    mode = "enforce";
    allowlistFile = "/etc/egress-allow.txt";
    auditLog = "/tmp/audit.jsonl";
    endpoints = [ ];
  });
  page = pkgs.writeTextDir "index.html" "upstream-ok\n";

  # sealed = false: the same guest without the network policy (the launcher
  # bug the self-test exists for). proxyPort: where the guest is told the
  # proxy is (3999: nothing listens).
  mkGuest = { sealed ? true, proxyPort ? 3128 }: { nodes, ... }:
    let
      proxyIP = nodes.proxy.networking.primaryIPAddress;
      upstreamIP = nodes.upstream.networking.primaryIPAddress;
    in
    {
      imports = [ ../modules/egress.nix ];
      microvmPolicy = {
        stateFile = "/etc/microvm-policy/state.env";
        stateAfter = [ "instance-data.service" ];
        egress = {
          nameservers = null;
          proxyAddress = "${proxyIP}:${toString proxyPort}";
          proxyEnvironment = true;
          sealProxyWait = 5;
        };
      };

      # Stand-in for cloud-init's write_files: the platform's instance data,
      # written by root at boot. No EGRESS_PROXY_ADDR, so the fallback counts.
      # The seal probe is the upstream's web port: reachable unless sealed.
      systemd.services.instance-data = {
        wantedBy = [ "multi-user.target" ];
        serviceConfig = { Type = "oneshot"; RemainAfterExit = true; };
        script = ''
          install -d -m 0755 /etc/microvm-policy
          printf 'EGRESS_POLICY=enforce\nEGRESS_SEAL_PROBE=${upstreamIP}:80\n' > /etc/microvm-policy/state.env
        '';
      };

      users.users.agent = { isNormalUser = true; };
      environment.systemPackages = [ pkgs.curl ];
      # The platform resolver (DHCP on a pod network); the seal must empty it.
      networking.nameservers = [ proxyIP ];

      # The pod's network policy: only the proxy, and replies.
      networking.nftables.enable = sealed;
      networking.nftables.tables = lib.mkIf sealed {
        podpolicy = {
          family = "inet";
          content = ''
            chain output {
              type filter hook output priority 0; policy drop;
              oif "lo" accept
              ct state established,related accept
              ip daddr ${proxyIP} tcp dport 3128 accept
            }
          '';
        };
      };
    };
in
pkgs.testers.runNixOSTest {
  name = "guest-pod-network";

  nodes = {
    upstream = { ... }: {
      networking.firewall.enable = false;
      services.openssh.enable = true;
      systemd.services.web = {
        wantedBy = [ "multi-user.target" ];
        serviceConfig.ExecStart = "${pkgs.python3}/bin/python3 -m http.server 80 -d ${page}";
      };
    };

    proxy = { ... }: {
      networking.firewall.enable = false;
      # The guest may reach `upstream` on :80 and :22, nothing else. `forbidden`
      # exists nowhere: the proxy refuses it by name, before any lookup.
      environment.etc."egress-allow.txt".text = "upstream:80\nupstream:22\n";
      systemd.services.egress = {
        wantedBy = [ "multi-user.target" ];
        after = [ "network-online.target" ];
        wants = [ "network-online.target" ];
        serviceConfig.ExecStart = "${egressProxy}/bin/egress-proxy -config ${proxyCfg}";
      };
    };

    guest = mkGuest { };
    unsealed = mkGuest { sealed = false; };
    noproxy = mkGuest { proxyPort = 3999; };
  };

  testScript = { nodes, ... }:
    let
      proxyIP = nodes.proxy.networking.primaryIPAddress;
    in
    ''
      # The guests' seal self-test runs at THEIR boot and gives the proxy
      # sealProxyWait (5s) to answer. With start_all() the proxy VM could
      # still be booting then, and an unsealed guest reported INCONCLUSIVE
      # instead of FAILED (CI, 2026-10-21): the race, not the guest, failed.
      # So the guests boot only once the proxy listens.
      upstream.start()
      proxy.start()
      upstream.wait_for_open_port(80)
      upstream.wait_for_open_port(22)
      proxy.wait_for_open_port(3128)
      for machine in (guest, unsealed, noproxy):
          machine.start()
      guest.wait_for_unit("egress-seal.service")

      with subtest("unsealed guest: the self-test FAILS the unit"):
          unsealed.wait_until_succeeds("systemctl is-failed egress-seal.service", timeout=120)
          marker = unsealed.succeed("cat /run/egress-seal-failed")
          print(marker)
          assert "egress-seal: FAILED" in marker, marker
          assert "${nodes.upstream.networking.primaryIPAddress}:80 succeeded" in marker, marker

      with subtest("proxy does not answer: INCONCLUSIVE, the unit fails"):
          noproxy.wait_until_succeeds("systemctl is-failed egress-seal.service", timeout=120)
          marker = noproxy.succeed("cat /run/egress-seal-failed")
          print(marker)
          assert "egress-seal: INCONCLUSIVE" in marker and "did not answer" in marker, marker

      with subtest("the seal reads the instance data and verifies"):
          seal = guest.succeed("journalctl -b -u egress-seal --no-pager")
          print(seal)
          assert "egress-seal: verified" in seal, "seal not verified"
          guest.succeed("systemctl is-active egress-seal.service")
          audit = proxy.succeed("cat /tmp/audit.jsonl")
          assert '"host":"egress-seal.invalid"' in audit, "the positive control never reached the proxy"
          guest.fail("test -e /run/egress-seal-failed")
          guest.succeed("test ! -s /etc/resolv.conf")
          guest.wait_for_unit("egress-proxy-env.service")
          penv = guest.succeed("journalctl -b -u egress-proxy-env --no-pager")
          assert "proxy environment exported to services and login shells (http://${proxyIP}:3128" in penv, penv

      with subtest("the proxy environment reaches services and login shells"):
          env = guest.succeed("systemctl show-environment")
          assert "HTTPS_PROXY=http://${proxyIP}:3128" in env, env
          assert "NO_PROXY=localhost,127.0.0.1,::1,${proxyIP}" in env, env
          shell = guest.succeed("su -l agent -c 'echo $https_proxy'").strip()
          assert shell == "http://${proxyIP}:3128", shell

      with subtest("allowlisted host via the proxy, from a service with no proxy flag"):
          out = guest.succeed(
              "systemd-run --wait --pipe -q -p User=agent curl -sS -m 10 http://upstream/index.html"
          )
          assert out.strip() == "upstream-ok", out

      with subtest("off-list host refused by the proxy and audited"):
          code = guest.succeed(
              "systemd-run --wait --pipe -q -p User=agent "
              "curl -s -o /dev/null -w '%{http_code}' -m 10 http://forbidden/index.html || true"
          ).strip()
          assert code == "403", f"forbidden host returned {code}, want 403"
          audit = proxy.succeed("cat /tmp/audit.jsonl")
          assert '"host":"forbidden","port":80,"path":"/index.html","decision":"deny"' in audit, audit

      with subtest("direct egress past the proxy is refused"):
          guest.fail("curl -sS -m 5 --noproxy '*' http://${nodes.upstream.networking.primaryIPAddress}/")

      with subtest("ssh goes through the proxy's CONNECT, address from the fallback"):
          guest.succeed("ssh -o BatchMode=yes -o StrictHostKeyChecking=no -o ConnectTimeout=10 upstream true 2>&1 | grep -q 'Permission denied' || true")
          audit = proxy.succeed("cat /tmp/audit.jsonl")
          assert '"kind":"connect","host":"upstream","port":22,"path":"","decision":"allow"' in audit, audit
    '';
}
