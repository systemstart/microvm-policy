# microvm-policy

Egress and filesystem containment for agent microVMs — the reusable policy
layer extracted from [claude-microvm](https://github.com/systemstart/claude-microvm).
Any [microvm.nix](https://github.com/microvm-nix/microvm.nix) consumer can run
the same tied-down scheme: default-deny egress through a credential-holding
host proxy, and a workspace that the guest cannot write through to the host.

It knows nothing about any particular agent or VM: a JSON config goes into the
proxy, a JSONL audit log comes out, and the guest modules take their layout
from the `microvmPolicy.*` options. The host-side glue — how the VM is
launched, how the netdev is sealed, which endpoints a given agent needs — stays
in the consumer.

## What's here

- **`proxy/`** — the egress proxy (Go, standard library only). An opaque
  `CONNECT` forward proxy with a host\:port allowlist, a reverse-proxy leg for
  LLM endpoints that strips client-supplied credentials and injects the key
  held on the host (path-allowlisted, no TLS interception), upstream-proxy
  chaining, and a one-line-per-decision JSONL audit log. Modes: `enforce`
  (deny off-allowlist) and `log` (allow but audit as `would_deny` — the
  "shadow" rung).
- **`egress-report.sh`** — host-side pcap summariser and live allowlist
  matcher, for observe-only monitoring (`packages.egress-report`).
- **`modules/egress.nix`** — guest module for the sealed modes: static
  resolver emptied under seal, a boot-time seal self-test, and ssh routed
  through the proxy.
- **`modules/workspace.nix`** — the workspace write-guard (read-only binds
  over host-executing config paths) and ephemeral overlay mode, plus
  `vm-work-diff`.
- **`modules/policy.nix`** — the `microvmPolicy.*` options that decouple the
  modules from any one VM's layout.
- **`allowlists/common.txt`** — generic development-infrastructure allowlist
  (registries, caches, source hosting). Agent-specific host lists belong to
  the consumer.

## Using it

```nix
{
  inputs.microvm-policy.url = "github:systemstart/microvm-policy";
  # in a nixosSystem:
  imports = [ microvm-policy.nixosModules.default ];
  # launcher glue uses:
  #   microvm-policy.packages.${system}.egress-proxy
  #   microvm-policy.packages.${system}.egress-report
  #   ${microvm-policy}/allowlists/common.txt
}
```

Set `microvmPolicy.stateFile` / `workspaceDir` / `agentHome` / `agentUser` if
your layout differs from the defaults (`/home/agent/.microvm-env`, `/work`,
`/home/agent`, `agent`).

## Checks

`nix flake check` runs the proxy's Go unit tests, the `egress-report`
summariser against a synthesised capture, and a multi-node `nixosTest`
(`egress-integration`) that drives the real proxy — reverse-proxy
strip/inject, path allowlist, `CONNECT` allow/deny with port grants, and
upstream-proxy chaining — across four VMs.

## Design

The rationale for each mechanism is in the header comment of the file that
implements it (`modules/*.nix`, `proxy/*.go`).
