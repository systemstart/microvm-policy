# Guest-side guard for workspace paths whose contents execute on the HOST
# later, which is why the VM boundary does not cover them: .git/hooks and
# .git/config run on the next host-side git invocation, .claude/commands,
# .claude/agents and .mcp.json are picked up by the next unsandboxed session
# that opens the directory, and .envrc runs under the host's direnv. A
# sandboxed session that can write these persists code past the VM teardown.
#
# Straight denial breaks a workflow this project actively uses — asking the
# agent to write a project skill or register an MCP server — so the
# guard is opt-in (WORKSPACE_GUARD=1) until it has lived a release under real
# use. It covers paths that exist at boot: it cannot make a file that is not
# there yet read-only, so a repo without .mcp.json is not protected against
# one being created. Defence in depth, not a boundary — the session contract
# says which state a run has.
#
# The same module carries WORKSPACE_MODE=ephemeral: the workspace
# becomes a guest-side overlay whose writes never reach the host — the
# complement of the guard. Passthrough stays the default: instant host-visible
# edits are the current contract and most of the point of virtiofs.
#
# Part of the microvm-policy layer — see modules/policy.nix for the options
# that decouple it from any one microVM's layout.
{ config, lib, pkgs, ... }:

let
  cfg = config.microvmPolicy;
  work = cfg.workspaceDir;
  # The systemd mount unit for a path, e.g. /work -> work.mount,
  # /home/agent -> home-agent.mount. Correct for the simple, space-free paths
  # a microVM share uses; used only for ordering.
  mountUnit = p: (lib.replaceStrings [ "/" ] [ "-" ] (lib.removePrefix "/" p)) + ".mount";

  # Shows what an ephemeral session changed: the overlay's upper layer holds
  # exactly the delta. Whiteouts (0:0 char devices) are deletions.
  vmWorkDiff = pkgs.writeShellScriptBin "vm-work-diff" ''
    # vm-work-diff [--patch] — list (or diff) this ephemeral session's changes
    # to the workspace. Copy anything worth keeping to ${cfg.agentHome} before
    # poweroff.
    up=/run/work-rw/upper
    lower=/run/work-lower
    if [ ! -d "$up" ]; then
      echo "vm-work-diff: not an ephemeral session (launch with WORKSPACE_MODE=ephemeral)" >&2
      exit 1
    fi
    patch=0
    [ "''${1:-}" = "--patch" ] && patch=1
    cd "$up"
    find . -mindepth 1 | sed 's|^\./||' | while IFS= read -r rel; do
      if [ -c "$up/$rel" ] && [ "$(stat -c %t:%T "$up/$rel")" = "0:0" ]; then
        echo "deleted:  $rel"
      elif [ -d "$up/$rel" ]; then
        continue
      elif [ -e "$lower/$rel" ]; then
        if [ "$patch" = 1 ]; then
          ${pkgs.diffutils}/bin/diff -u "$lower/$rel" "${work}/$rel" || true
        else
          echo "modified: $rel"
        fi
      else
        if [ "$patch" = 1 ]; then
          ${pkgs.diffutils}/bin/diff -u /dev/null "${work}/$rel" || true
        else
          echo "created:  $rel"
        fi
      fi
    done
  '';
in
{
  imports = [ ./policy.nix ];

  options.microvmPolicy.workspaceGuard = {
    paths = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [
        ".git/hooks"
        ".git/config"
        ".mcp.json"
        ".claude/commands"
        ".claude/agents"
        ".envrc"
      ];
      description = ''
        Paths under the workspace made read-only inside the guest when the
        session runs with WORKSPACE_GUARD=1. Relative to the workspace root;
        entries that do not exist at boot are skipped.
      '';
    };
  };

  config = {
    environment.systemPackages = [ vmWorkDiff ];

    systemd.services.work-ephemeral = {
      description = "Guest-side overlay over the workspace: writes never reach the host";
      after = [ (mountUnit work) ] ++ cfg.stateAfter;
      before = [ "workspace-guard.service" "getty@hvc0.service" ];
      wantedBy = [ "multi-user.target" ];
      # NixOS unit scripts default to coreutils/sed/grep on PATH — mount is
      # not among them. Found by the first real boot.
      path = [ pkgs.util-linux ];
      serviceConfig = {
        Type = "oneshot";
        RemainAfterExit = true;
      };
      script = ''
        mode=""
        if [ -f ${cfg.stateFile} ]; then
          mode=$(${pkgs.gnused}/bin/sed -n 's/^WORKSPACE_MODE=//p' ${cfg.stateFile} | tail -n1)
        fi
        [ "$mode" = "ephemeral" ] || exit 0

        # Keep the pristine host view reachable (for vm-work-diff and the
        # overlay's lowerdir) without disturbing systemd's workspace mount: a
        # bind, not a move. systemd makes / shared, so the overlay we mount
        # below would propagate into this bind and the "lower" would show the
        # upper's writes (vm-work-diff then calling every new file "modified").
        # --make-private detaches the bind from that peer group so it stays
        # pristine.
        mkdir -p /run/work-lower /run/work-rw
        mount --bind ${work} /run/work-lower
        mount --make-private /run/work-lower

        # The upper layer is RAM (its own tmpfs, so a runaway write fills
        # this mount, not /run): session writes cost memory and vanish at
        # poweroff — that is the feature. Overlay root attributes come from
        # the upper dir, so it must be the agent's.
        mount -t tmpfs -o mode=0755 tmpfs /run/work-rw
        install -d -o ${cfg.agentUser} -g ${cfg.agentUser} /run/work-rw/upper
        mkdir -p /run/work-rw/work
        mount -t overlay overlay \
          -o lowerdir=/run/work-lower,upperdir=/run/work-rw/upper,workdir=/run/work-rw/work \
          ${work}
        echo "work-ephemeral: ${work} is an overlay — writes stay in the VM (vm-work-diff lists them)"
      '';
    };

    systemd.services.workspace-guard = {
      description = "Read-only binds over workspace paths that execute on the host";
      after = [ (mountUnit work) ] ++ cfg.stateAfter ++ [ "work-ephemeral.service" ];
      before = [ "getty@hvc0.service" ];
      wantedBy = [ "multi-user.target" ];
      path = [ pkgs.util-linux ]; # mount — see work-ephemeral
      serviceConfig = {
        Type = "oneshot";
        RemainAfterExit = true;
      };
      script = ''
        guard=""
        if [ -f ${cfg.stateFile} ]; then
          guard=$(${pkgs.gnused}/bin/sed -n 's/^WORKSPACE_GUARD=//p' ${cfg.stateFile} | tail -n1)
        fi
        [ "$guard" = "1" ] || exit 0

        guarded=""
        for rel in ${lib.escapeShellArgs cfg.workspaceGuard.paths}; do
          p="${work}/$rel"
          [ -e "$p" ] || continue
          # A bind of a path over itself plus a read-only remount of that
          # bind: the write fails with EROFS inside the guest while the host
          # view stays untouched. The agent user cannot undo it — the mounts
          # belong to the init namespace, which locks them against detach
          # from any user namespace the agent can create.
          mount --bind "$p" "$p"
          mount -o remount,bind,ro "$p"
          guarded="$guarded $rel"
        done
        if [ -n "$guarded" ]; then
          echo "workspace-guard: read-only:$guarded"
        else
          echo "workspace-guard: enabled, but none of the guarded paths exist in ${work}"
        fi
      '';
    };
  };
}
