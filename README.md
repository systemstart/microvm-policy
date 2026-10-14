# microvm-policy

Egress and filesystem containment for microVMs, as a reusable policy
layer. Any [microvm.nix](https://github.com/microvm-nix/microvm.nix) consumer
can run the same tied-down scheme: default-deny egress through a
credential-holding host proxy, and a workspace that the guest cannot write
through to the host.

It knows nothing about any particular VM or what runs in it: a JSON config
goes into the proxy, a JSONL audit log comes out, and the guest modules take
their layout from the `microvmPolicy.*` options. The host-side glue — how the
VM is launched, how the netdev is sealed, which endpoints a given workload
needs — stays in the consumer.

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
  resolver emptied under seal, a boot-time seal self-test, ssh routed
  through the proxy, and the proxy env handed to system services that need
  the network (`microvmPolicy.proxyEnv.services`, default `nix-daemon`, so
  substitutes and fixed-output fetches work while sealed).
- **`modules/workspace.nix`** — the workspace write-guard (read-only binds
  over host-executing config paths) and ephemeral overlay mode, plus
  `vm-work-diff`.
- **`modules/policy.nix`** — the `microvmPolicy.*` options that decouple the
  modules from any one VM's layout.
- **`allowlists/common.txt`** — generic development-infrastructure allowlist
  (registries, caches, source hosting). Workload-specific host lists belong to
  the consumer.

## Using it

```nix
{
  # pin a release: github:systemstart/microvm-policy/vX.Y.Z
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

For a complete consumer, see
[claude-microvm](https://github.com/systemstart/claude-microvm): its
`flake.nix` imports the modules, builds the per-agent allowlists on top of
`common.txt`, and its launcher seals the VM's netdev and runs `egress-proxy`
and `egress-report` on the host.

## Checks

`nix flake check` runs the proxy's Go unit tests, the `egress-report`
summariser against a synthesised capture, and a multi-node `nixosTest`
(`egress-integration`) that drives the real proxy — reverse-proxy
strip/inject, path allowlist, `CONNECT` allow/deny with port grants, and
upstream-proxy chaining — across four VMs.

## Development

```sh
nix develop          # pinned Go (go-overlay), golangci-lint, gofumpt, release tooling
make hooks           # once per clone: lint on commit, reject unsigned commits on push
make lint test build # the Go gates CI runs; `make test` enforces 80% coverage
make check           # nix flake check, including the nixosTests (needs KVM)
make diff-closures   # what a flake.lock bump actually changes
```

Commits follow [Conventional Commits](https://www.conventionalcommits.org/):
the type decides the next version and the release-notes section.

## Releasing

```sh
make release-tag-preview   # the version gsemver would cut
make release-tag           # write VERSION, commit, signed tag, push
```

The tag push runs CI's `release` job: `make release` renders the notes with
git-cliff (`cliff.toml`) and publishes the GitHub release. `make
release-notes` previews them. `VERSION` is the single source of truth; the
flake reads it for the package version and stamps it into `egress-proxy
-version`.

## Design

The rationale for each mechanism is in the header comment of the file that
implements it (`modules/*.nix`, `proxy/*.go`).
