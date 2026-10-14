# Guest half of the restricted egress modes (EGRESS_POLICY=shadow|enforce).
# The host half — restrict=on, the guestfwd hole, the proxy itself — lives in
# the launcher and proxy/; this module only makes the guest behave well inside
# a sealed netdev. Everything here is inert under open/monitor/alert: the mode
# is read from the policy state file at boot.
#
# Part of the microvm-policy layer — see modules/policy.nix for the options
# that decouple it from any one microVM's layout.
{ config, lib, pkgs, ... }:

let
  cfg = config.microvmPolicy;
in
{
  imports = [ ./policy.nix ];

  config = {
    environment.systemPackages = [ pkgs.socat ];

    # A static resolv.conf pointing at slirp's resolver — the same resolver
    # DHCP would hand out, so the open modes behave as before. dhcpcd keeps
    # its hands off the file, which is what lets the seal service's emptying
    # of it stick for the whole session.
    networking.dhcpcd.extraConfig = "nohook resolv.conf";
    networking.nameservers = [ "10.0.2.3" ];

    # ssh for every host goes through this wrapper, which connects directly in
    # the open modes and speaks HTTP CONNECT to the egress proxy in the sealed
    # ones. System-wide ssh_config keeps the persistent agent home untouched —
    # the same home may serve sealed and open sessions on different days.
    programs.ssh.extraConfig = ''
      Host *
        ProxyCommand ${pkgs.writeShellScript "microvm-policy-ssh-proxy" ''
          policy=""
          if [ -f ${cfg.stateFile} ]; then
            policy=$(${pkgs.gnused}/bin/sed -n 's/^EGRESS_POLICY=//p' ${cfg.stateFile} | tail -n1)
          fi
          case "$policy" in
            shadow|enforce)
              addr=$(${pkgs.gnused}/bin/sed -n 's/^EGRESS_PROXY_ADDR=//p' ${cfg.stateFile} | tail -n1)
              exec ${pkgs.socat}/bin/socat STDIO "PROXY:''${addr%%:*}:$1:$2,proxyport=''${addr##*:}"
              ;;
            *)
              exec ${pkgs.socat}/bin/socat STDIO "TCP:$1:$2"
              ;;
          esac
        ''} %h %p
    '';

    # A fresh agent home has no known_hosts and no terminal to answer the
    # first-connection prompt, so git-over-SSH to the one host the default
    # allowlist grants port 22 for would always fail host-key verification.
    # Pin GitHub's published keys (https://api.github.com/meta, fetched
    # 2026-10-14) instead of weakening to accept-new.
    programs.ssh.knownHosts."github.com" = {
      publicKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl";
    };

    systemd.services.egress-seal = {
      description = "Verify the sealed netdev and remove the blackholed resolver";
      after = [ "network-online.target" "home-agent.mount" ];
      wants = [ "network-online.target" ];
      before = [ "getty@hvc0.service" ];
      wantedBy = [ "multi-user.target" ];
      serviceConfig = {
        Type = "oneshot";
        RemainAfterExit = true;
      };
      script = ''
        policy=""
        if [ -f ${cfg.stateFile} ]; then
          policy=$(${pkgs.gnused}/bin/sed -n 's/^EGRESS_POLICY=//p' ${cfg.stateFile} | tail -n1)
        fi
        case "$policy" in shadow|enforce) ;; *) exit 0 ;; esac

        # Under restrict=on, slirp silently *drops* UDP to 10.0.2.3, so a
        # configured resolver turns every blocked lookup into a five-second
        # hang — the worst failure mode this track has. An empty resolv.conf
        # makes getaddrinfo fail instantly; the proxy does all resolution.
        rm -f /etc/resolv.conf
        : > /etc/resolv.conf

        # Boot-time seal self-test (Anthropic's containment lesson: their
        # breaches happened in environments *believed* sealed and never
        # verified). Direct TCP must be refused by slirp immediately; a
        # connect that succeeds means the netdev is not restricted at all.
        if timeout 3 ${pkgs.bash}/bin/bash -c 'echo > /dev/tcp/1.1.1.1/443' 2>/dev/null; then
          {
            echo "egress-seal: FAILED under EGRESS_POLICY=$policy — direct egress to"
            echo "1.1.1.1:443 succeeded, so the netdev is NOT restricted. The session is"
            echo "running with today's open networking while claiming to be sealed."
          } > /run/egress-seal-failed
          cat /run/egress-seal-failed >&2
          # Recorded, not a boot failure: the login shell refuses to start the
          # agent on this flag, which is the loud stop — bricking the boot
          # would hide the message.
          exit 0
        fi
        echo "egress-seal: verified — direct egress blocked, traffic goes via the proxy"
      '';
    };
  };
}
