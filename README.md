<p align="center"><img src="https://raw.githubusercontent.com/grpc-transports/brand/main/social/grpc-transports.png" alt="grpc-transports/control" width="720"></p>

# control

[![Go Reference](https://pkg.go.dev/badge/github.com/grpc-transports/control.svg)](https://pkg.go.dev/github.com/grpc-transports/control)
[![CI](https://github.com/grpc-transports/control/actions/workflows/ci.yml/badge.svg)](https://github.com/grpc-transports/control/actions/workflows/ci.yml)
[![License: BSD-3-Clause](https://img.shields.io/badge/License-BSD--3--Clause-blue.svg)](LICENSE)

The listener for a daemon's gRPC **admin** API — the port an operator's CLI talks to, as opposed to the one its users do. It listens on a **0600 unix socket**, or on **TCP with mandatory mutual TLS**, and says **who called** for the audit line. Pure Go, `CGO_ENABLED=0`.

## Why

An admin API can reconfigure, drain or stop the daemon, so "who may reach it" has two acceptable answers and this package accepts no other:

| | who can connect |
|---|---|
| `unix:///run/mydaemon/admin.sock` | the daemon's own user: the socket is mode 0600 |
| `host:port` | a client presenting a certificate signed by the CA the daemon names, to a server whose certificate the client verifies in turn |

There is no plaintext TCP, and **loopback is not an exception**: any local account can connect to `127.0.0.1`, so an admin API on loopback without client certificates is open to every user of the machine.

## Use

```go
cfg := control.Config{Listen: "unix:///run/mydaemon/admin.sock"}
// or: control.Config{Listen: ":8443", TLSCertFile: "srv.crt", TLSKeyFile: "srv.key", ClientCAFile: "ops-ca.pem"}

if err := cfg.Check(); err != nil { // at config load: no network, no files
    log.Fatal(err)
}
lis, opts, err := control.Listen(cfg)
if err != nil {
    log.Fatal(err)
}
gs := grpc.NewServer(opts...)
adminpb.RegisterAdminServer(gs, impl)
go gs.Serve(lis)
```

In a handler:

```go
log.Printf("admin: %s called Drain", control.Caller(ctx)) // "uid=1000", or "cn=ops-laptop"
```

A client — a CLI, or the daemon's own tests:

```go
cc, err := control.Dial(control.ClientConfig{Target: "unix:///run/mydaemon/admin.sock"})
cc, err := control.Dial(control.ClientConfig{Target: "admin.example.org:8443",
    CertFile: "me.crt", KeyFile: "me.key", ServerCAFile: "daemon-ca.pem"})
```

## What `Check` refuses

- TCP without all three of `TLSCertFile`, `TLSKeyFile`, `ClientCAFile` — loopback included;
- a unix socket with any of them: its file mode is its access control, and a certificate beside it would suggest otherwise;
- a relative socket path, and any scheme other than `unix:`.

## The unix socket

**It is never reachable by another user, not even for an instant.** `bind(2)` creates the socket file with mode `0777 &^ umask`, so with the usual umask it is connectable by everyone until a `chmod` follows. Narrowing the umask around the bind would close that window but open another: the umask belongs to the process, not the goroutine, and every file other goroutines created meanwhile would silently get the narrower mode. So the socket is bound inside a fresh `0700` directory next to the requested path, `chmod`'ed to `0600` there, and only then hard-linked into place.

**A running daemon's socket is never stolen.** A socket file already at the path is removed only if connecting to it is *refused* — nothing listens. If something answers, `Listen` fails naming the path. If it cannot tell (another user's socket, say), it fails too. A file at the path that is not a socket is never touched. `link(2)` refuses to replace a file, so one that appears between that check and the bind is left alone as well.

**Closing the listener removes the socket file** — if it is still the one this listener created.

**The peer uid comes from the kernel** at connection time — `SO_PEERCRED` on Linux, `LOCAL_PEERCRED` (what `getpeereid(3)` uses) on darwin and FreeBSD — and a client cannot forge it.

**The client checks who is listening.** `Dial` reads the uid of the process behind the socket the same way and refuses to send anything unless it is the client's own uid, root's, or `ClientConfig.ServerUID` (a uid trusted in addition, for a daemon running as its own account). A socket in a directory others can write could have been bound first by an impostor; the RPC then fails naming the uid found. Where the platform has no peer credentials (Windows, the BSDs other than FreeBSD) the uid is not checked: keep the socket in a directory only trusted accounts can write.

```go
uid := uint32(997) // the daemon's account
cc, err := control.Dial(control.ClientConfig{Target: "unix:///run/mydaemon/admin.sock", ServerUID: &uid})
```

The private directory costs up to 13 bytes of the socket address limit (104 bytes on darwin, 108 on Linux) while binding; a path that would not fit is refused with that reason rather than an `EINVAL`.

## TCP

The server requires and verifies a client certificate against `ClientCAFile` (`tls.RequireAndVerifyClientCert`), accepts TLS 1.2 at the least, and negotiates TLS 1.3 whenever the client offers it. `Caller` reports the verified certificate's subject CN, or its whole subject when the CN is empty.

## Platforms

| | peer identity | socket mode |
|---|---|---|
| Linux | `uid=` via `SO_PEERCRED` | 0600, never exposed |
| darwin, FreeBSD | `uid=` via `LOCAL_PEERCRED` | 0600, never exposed |
| other unixes | `unix` | 0600, never exposed |
| Windows | `unix` — there is no uid | none: who may connect is the ACL the socket inherits from its directory, so put it in one only the daemon's account can open |

## Sibling

The rest of [grpc-transports](https://github.com/grpc-transports) carries gRPC where TCP cannot go — [vsock](https://github.com/grpc-transports/vsock), [websocket](https://github.com/grpc-transports/websocket), [webrtc](https://github.com/grpc-transports/webrtc). This one is about where gRPC *should not* go.

## License

BSD-3-Clause.
