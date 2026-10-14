# Shared options for the policy layer (egress.nix, workspace.nix, and
# the host-side proxy in proxy/). These are the only couplings between the
# reusable policy layer and the VM it runs in: the state file that carries
# the session's policy (and the units that provide it), the workspace mount,
# and the home and user the guest workload runs as. Defaults match
# claude-microvm's conventions; another consumer overrides them to its own
# layout.
#
# The state file is a transport, not a launcher feature. A microvm.nix host
# writes it into a share before boot; a guest whose platform owns the
# hypervisor (KubeVirt, a cloud) receives the same KEY=value lines as
# instance data instead (e.g. cloud-init `write_files` into /etc) and names
# the unit that writes them in `stateAfter`. Either way the guest workload
# must not be able to write it.
{ config, lib, ... }:

let
  cfg = config.microvmPolicy;
  # The systemd mount unit for a path, e.g. /home/agent -> home-agent.mount.
  mountUnit = p: (lib.replaceStrings [ "/" ] [ "-" ] (lib.removePrefix "/" p)) + ".mount";
in
{
  options.microvmPolicy = {
    stateFile = lib.mkOption {
      type = lib.types.str;
      default = "/home/agent/.microvm-env";
      description = ''
        File carrying the session's policy knobs (EGRESS_POLICY,
        EGRESS_PROXY_ADDR, WORKSPACE_MODE, WORKSPACE_GUARD), one KEY=value
        per line. A microvm.nix launcher writes it before boot; a guest on a
        platform that owns the hypervisor gets it from its instance data (see
        stateAfter). The guest services read it; it must not be writable from
        inside the guest by the workload.
      '';
    };
    stateAfter = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [ (mountUnit cfg.agentHome) ];
      defaultText = lib.literalExpression ''[ "<agentHome's mount unit>" ] # home-agent.mount'';
      example = [ "cloud-init.service" ];
      description = ''
        systemd units that make stateFile available. The services that read
        it (egress-seal, work-ephemeral, workspace-guard) are ordered after
        them. The default is the agent home's mount, where a microvm.nix
        launcher puts the file; a guest that receives its policy as instance
        data names the unit that writes it, e.g. cloud-init.service for
        cloud-init's write_files.
      '';
    };
    workspaceDir = lib.mkOption {
      type = lib.types.str;
      default = "/work";
      description = "Guest mount point of the project workspace.";
    };
    agentHome = lib.mkOption {
      type = lib.types.str;
      default = "/home/agent";
      description = "Guest home directory of the unprivileged workload user.";
    };
    agentUser = lib.mkOption {
      type = lib.types.str;
      default = "agent";
      description = "Unprivileged user the guest workload runs as (owns the ephemeral overlay upper).";
    };
  };
}
