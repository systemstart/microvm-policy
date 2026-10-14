# Shared options for the agent-policy layer (egress.nix, workspace.nix, and
# the host-side proxy in proxy/). These are the only couplings between the
# reusable policy layer and the microVM it runs in: the state file the host
# launcher writes, the workspace mount, the agent's home and user. Defaults
# match claude-microvm's conventions, so importing the layer there changes
# nothing; another microvm.nix consumer overrides them to its own layout.
#
# This is the seam the layer is extracted along (attic/TODO.md Phase 9): with
# these in place the split to a standalone repo is `git mv` plus one flake
# input, no code change.
{ lib, ... }:
{
  options.microvmPolicy = {
    stateFile = lib.mkOption {
      type = lib.types.str;
      default = "/home/agent/.microvm-env";
      description = ''
        File the host launcher writes before boot, carrying the session's
        policy knobs (EGRESS_POLICY, EGRESS_PROXY_ADDR, WORKSPACE_MODE,
        WORKSPACE_GUARD). The guest services read it; it must not be written
        from inside the guest.
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
      description = "Guest home directory of the agent user.";
    };
    agentUser = lib.mkOption {
      type = lib.types.str;
      default = "agent";
      description = "Unprivileged user the agent runs as (owns the ephemeral overlay upper).";
    };
  };
}
