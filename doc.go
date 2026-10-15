// Package geph5_go is the Go port of the geph5 client core.
//
// This module is a byte-for-byte wire-compatible reimplementation of the
// geph5 client (binaries/geph5-client in the Rust workspace). It speaks the
// same JSON-RPC, sosistab3/picomux framing, and ed25519-signed route formats
// as the Rust broker and exits, so a Go client connects to a Rust broker and
// tunnels through Rust exits transparently.
//
// The entrypoint is cmd/geph-client, which parses flags, loads the YAML
// config, and races the same eight concurrent services as Rust's client_main:
// socks5, http_proxy, pac, port_forward, vpn, auth, bw_token_refresh, and the
// control RPC server (tcp/unix/pipe). In dry_run mode only the control RPC
// server runs.
//
// The client core is also embeddable directly (internal/clientlib) and as a
// provider plugin for the goose proxy-pool engine (plugins/geph), which
// advertises the client's loopback SOCKS5 listener as a goose outbound once a
// tunnel to an exit is live. For one-process deployments, internal/exitlib
// implements the geph5 exit server (the c2e serving path) as an embeddable
// library, so client and exit can run in a single process with no Rust
// binary; the plugin's "embedded_exit" option wires exactly that.
//
// See the package README for the full architecture, configuration reference,
// and wire-compatibility notes. Key packages:
//
//   - internal/nanorpc   — JSON-RPC 2.0 client + server (newline-delimited)
//   - internal/sillad    — Dialer/Pipe abstractions and combinators
//   - internal/brokerproto — broker client, signed routes, exit descriptors
//   - internal/session   — session manager tying routes, dialers, and handshakes
//   - internal/exitlib   — embeddable geph5 exit server (standalone mode)
//   - internal/vpn       — gVisor userspace TCP/IP stack + stdio/fd VPN framing
//   - internal/control   — control RPC service (13 snake_case methods)
//   - internal/clientlib — embeddable client bundle (auth + sessions + SOCKS5)
//   - plugins/geph       — goose provider plugin embedding the client core
//
// gVisor is pinned to v0.0.0-20260218152508-eed1cebf761e; do not upgrade
// without verifying the build (later snapshots carry a packaging defect that
// breaks `go build`).
//
// Build, vet, and test:
//
//	go build ./... && go vet ./... && go test ./...
package geph5_go
