# Guest half of the restricted egress modes (EGRESS_POLICY=shadow|enforce).
# The host half — the seal itself and the proxy — lives outside the guest;
# this module only makes the guest behave well inside a sealed network.
# Everything here is inert under open/monitor/alert: the mode is read from
# the policy state file at boot.
#
# The seal is the platform's, and this module does not care which one it is:
#
#   - microvm.nix (claude-microvm): QEMU's user-mode netdev with restrict=on
#     and one guestfwd hole to a host-side proxy; slirp's resolver at
#     10.0.2.3. These are the defaults.
#   - a platform that owns the hypervisor (KubeVirt on a pod network): a
#     default-deny network policy for the VM whose only egress is the proxy's
#     address; the resolver is whatever DHCP hands out
#     (`egress.nameservers = null`), and the proxy settings reach the guest's
#     services and login shells through `egress.proxyEnvironment`, because no
#     launcher writes them into a session.
#
# Part of the microvm-policy layer — see modules/policy.nix for the options
# that decouple it from any one VM's layout.
{ config, lib, pkgs, ... }:

let
  cfg = config.microvmPolicy;
  ecfg = cfg.egress;
  # Reads the proxy address from the state file into $addr; with
  # egress.proxyAddress set, that is the fallback. (Spliced into the scripts
  # so that, without a fallback, they are byte-for-byte what they were.)
  addrLine = "addr=$(${pkgs.gnused}/bin/sed -n 's/^EGRESS_PROXY_ADDR=//p' ${cfg.stateFile} | tail -n1)";
  addrFallback = lib.optionalString (ecfg.proxyAddress != null)
    "\n[ -n \"$addr\" ] || addr=${lib.escapeShellArg ecfg.proxyAddress}";
in
{
  imports = [ ./policy.nix ];

  options.microvmPolicy.proxyEnv = {
    file = lib.mkOption {
      type = lib.types.str;
      default = "/run/microvm-policy/proxy.env";
      description = ''
        Environment file carrying HTTP(S)_PROXY / NO_PROXY for the egress
        proxy, written at boot in the sealed modes only (absent otherwise).
        System services that should reach the network through the proxy read
        it with `EnvironmentFile=-<file>`; `services` wires that up.
      '';
    };
    services = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [ "nix-daemon" ];
      example = [ "nix-daemon" "docker" "containerd" ];
      description = ''
        systemd services (without `.service`) that get the proxy env file.
        System services inherit neither the workload's proxy variables nor
        any global ones, so under a sealed netdev they have no route out
        unless listed here. nix-daemon is the default because, with
        `NIX_REMOTE=daemon`, it performs every substitute download and every
        fixed-output fetch.
      '';
    };
  };

  options.microvmPolicy.egress = {
    nameservers = lib.mkOption {
      type = lib.types.nullOr (lib.types.listOf lib.types.str);
      default = [ "10.0.2.3" ];
      example = null;
      description = ''
        The guest's resolver in the open modes, written as a static
        resolv.conf that DHCP leaves alone (so the seal's emptying of it
        sticks). The default is slirp's resolver, i.e. what QEMU's user-mode
        DHCP would hand out. `null` keeps the platform's own (DHCP-supplied)
        resolver, for networks where the resolver's address is not fixed; the
        seal still empties resolv.conf.
      '';
    };
    proxyAddress = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = null;
      example = "10.96.0.31:3128";
      description = ''
        host:port of the egress proxy, used when the state file carries no
        EGRESS_PROXY_ADDR. null: the state file is the only source (a
        microvm.nix launcher always writes it).
      '';
    };
    proxyEnvironment = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = ''
        Under the sealed modes, hand the proxy env file (proxyEnv.file) to
        every service started after it (systemctl set-environment) and to
        login shells (sourced from /etc/profile), not only to
        proxyEnv.services. For platforms where no launcher writes the proxy
        variables into the session; off by default because a microvm.nix
        launcher does exactly that itself.
      '';
    };
    noProxy = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [ "localhost" "127.0.0.1" "::1" ];
      description = "NO_PROXY entries of the proxy env file; the proxy's own host is appended.";
    };
  };

  config = lib.mkMerge [ {
    environment.systemPackages = [ pkgs.socat ];

    # A static resolv.conf pointing at slirp's resolver — the same resolver
    # DHCP would hand out, so the open modes behave as before. dhcpcd keeps
    # its hands off the file, which is what lets the seal service's emptying
    # of it stick for the whole session. With nameservers = null the platform's
    # DHCP owns the file; the seal empties it once, at boot.
    networking.dhcpcd.extraConfig = lib.mkIf (ecfg.nameservers != null) "nohook resolv.conf";
    networking.nameservers = lib.mkIf (ecfg.nameservers != null) ecfg.nameservers;

    environment.extraInit = lib.mkIf ecfg.proxyEnvironment ''
      if [ -r ${cfg.proxyEnv.file} ]; then
        set -a; . ${cfg.proxyEnv.file}; set +a
      fi
    '';

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
              ${addrLine}${addrFallback}
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
      after = [ "network-online.target" ] ++ cfg.stateAfter;
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

    # The workload gets its proxy variables from the state file; system
    # services get nothing, so under a sealed netdev they have no route out.
    # For nix-daemon that silently breaks every substitute download and
    # fixed-output fetch while `nix` itself (client-side flake fetches) keeps
    # working. Write the proxy env once at boot, sealed modes only, and hand
    # it to the listed services. Lowercase variants are the ones curl honours
    # for plain http and the ones Nix's fetchers pass through to builds.
    # With egress.proxyEnvironment the same file also goes to every later
    # service and to login shells, which must then start after it.
    systemd.services.egress-proxy-env = {
      description = "Proxy env for system services under a sealed egress netdev";
      unitConfig.RequiresMountsFor = [ (dirOf cfg.stateFile) ];
      # Pulled in by, and ordered before, each listed service — not via
      # multi-user.target alone, because socket-activated daemons such as
      # nix-daemon can start before it.
      after = lib.mkIf ecfg.proxyEnvironment cfg.stateAfter;
      before = map (s: "${s}.service") cfg.proxyEnv.services
        ++ lib.optional ecfg.proxyEnvironment "systemd-user-sessions.service";
      wantedBy = [ "multi-user.target" ] ++ map (s: "${s}.service") cfg.proxyEnv.services;
      serviceConfig = {
        Type = "oneshot";
        RemainAfterExit = true;
      };
      script = ''
        rm -f ${cfg.proxyEnv.file}
        policy="" addr=""
        if [ -f ${cfg.stateFile} ]; then
          policy=$(${pkgs.gnused}/bin/sed -n 's/^EGRESS_POLICY=//p' ${cfg.stateFile} | tail -n1)
          ${addrLine}
        fi${addrFallback}
        case "$policy" in shadow|enforce) ;; *) exit 0 ;; esac
        if [ -z "$addr" ]; then
          echo "egress-proxy-env: EGRESS_POLICY=$policy but EGRESS_PROXY_ADDR is unset — not writing ${cfg.proxyEnv.file}" >&2
          exit 0
        fi
        mkdir -p "$(dirname ${cfg.proxyEnv.file})"
        umask 022
        cat > ${cfg.proxyEnv.file} <<EOF
        HTTP_PROXY=http://$addr
        HTTPS_PROXY=http://$addr
        http_proxy=http://$addr
        https_proxy=http://$addr
        NO_PROXY=${lib.concatStringsSep "," ecfg.noProxy},''${addr%:*}
        no_proxy=${lib.concatStringsSep "," ecfg.noProxy},''${addr%:*}
        EOF
        echo "egress-proxy-env: ${lib.concatStringsSep ", " cfg.proxyEnv.services} will use the egress proxy at $addr"
      '' + lib.optionalString ecfg.proxyEnvironment ''
        # One KEY=value per line, no spaces: safe to word-split.
        ${config.systemd.package}/bin/systemctl set-environment $(cat ${cfg.proxyEnv.file})
        echo "egress-proxy-env: proxy environment exported to services and login shells (http://$addr)"
      '';
    };

  } {
    systemd.services = lib.genAttrs cfg.proxyEnv.services (_: {
      serviceConfig.EnvironmentFile = [ "-${cfg.proxyEnv.file}" ];
    });
  } ];
}
