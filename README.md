# VpnHood.Net.Proxies

**Standard proxy clients and servers for .NET** — SOCKS5, SOCKS4/4a, HTTP, and HTTPS, in one small cross-platform library with no native dependencies, built on `async`/`await` and `Span<byte>`.

This is an **independent, general-purpose library**: it implements the standard proxy protocols (RFC 1928, RFC 1929, HTTP CONNECT) and has no dependency on any VPN product. Use it in any .NET application to add proxy support, embed a lightweight proxy server, bridge traffic between networks, or test proxy-aware software. It is maintained by [VpnHood](https://github.com/vpnhood/vpnhood) and battle-tested there in production, but it works entirely on its own.

## Feature matrix

| Protocol | Client | Server |
| --- | --- | --- |
| **SOCKS5** (RFC 1928) | TCP CONNECT, UDP ASSOCIATE, username/password auth (RFC 1929), remote DNS (domain addresses), IPv4 + IPv6 | TCP CONNECT, UDP ASSOCIATE with source validation, username/password auth, IPv4 + IPv6 |
| **SOCKS4 / 4a** | TCP CONNECT, user-id, host names via SOCKS4a | — |
| **HTTP proxy** | CONNECT tunnels, Basic auth, optional TLS to the proxy itself | CONNECT tunnels + plain `GET/POST …` forwarding, Basic auth |
| **HTTPS proxy** (TLS between client and proxy) | `HttpProxyClient` with `UseTls = true` | `HttpsProxyServer` with your `X509Certificate2` |

Common properties:

* Standalone and reusable — plain .NET, no VPN or VpnHood runtime required; the only dependency is `Microsoft.Extensions.Logging.Abstractions`
* Fully asynchronous, cancellation-aware I/O; no blocking calls
* Handshake and connect timeouts with sensible defaults ([options classes](https://github.com/vpnhood/VpnHood.Net.Proxies/blob/main/src/VpnHood.Net.Proxies/Socks5ProxyServers/Socks5ProxyServerOptions.cs))
* Built for memory-constrained hosts (mobile network extensions, small containers): every per-connection resource is bounded — an optional `MaxConnections` cap (unlimited by default), capped header sizes, bounded UDP destination tables, and a TCP half-close linger timeout so idle peers cannot retain tunnels indefinitely
* Correct TCP half-close: a peer that shuts down its send side still receives the full response through the tunnel
* Low-allocation hot paths (`ArrayPool`, pooled tunnel buffers, spans)
* Optional `Microsoft.Extensions.Logging` integration — pass an `ILogger`, or nothing
* Privacy-friendly: SOCKS5 client sends host names to the proxy for **remote DNS resolution** (no local lookup or DNS leak)
* SOCKS5 UDP relay only accepts datagrams from the associated client and from destinations that client has contacted — third parties cannot inject packets into an association

## Installation

```bash
dotnet add package VpnHood.Net.Proxies
```

Or add the project to your solution and reference it directly.

## Quick start

Each example below runs as a test in CI ([ReadmeExampleTests.cs](https://github.com/vpnhood/VpnHood.Net.Proxies/blob/main/tests/VpnHood.Net.Proxies.Tests/ReadmeExampleTests.cs)). Their namespaces are `VpnHood.Net.Proxies.Socks5ProxyServers`, `.Socks5ProxyClients`, `.HttpProxyServers`, `.HttpProxyClients` and `.Socks4ProxyClients`.

### Run a SOCKS5 proxy server

```csharp Snippet:Socks5Server
using var server = new Socks5ProxyServer(new Socks5ProxyServerOptions {
    ListenEndPoint = new IPEndPoint(IPAddress.Loopback, 0), // 0: the system picks a free port
    Username = null, // set a user name to require RFC 1929 authentication
    Password = null
});

server.Start(); // or: await server.RunAsync(cancellationToken);
var proxyEndPoint = server.ListenerEndPoint;
```

### Connect through a SOCKS5 proxy (TCP)

```csharp Snippet:Socks5Connect
var client = new Socks5ProxyClient(new Socks5ProxyClientOptions {
    ProxyEndPoint = proxyEndPoint
});

using var tcp = new TcpClient();

// A host name goes to the proxy as a SOCKS5 domain name, so the proxy resolves it: no local DNS query.
await client.ConnectAsync(tcp, destinationHost, destinationPort, CancellationToken.None);

var stream = tcp.GetStream(); // the tunnel: speak HTTP, TLS or anything else
```

A single `Socks5ProxyClient` instance is reusable across many connections; the handshake is negotiated per connection.

### Send UDP through a SOCKS5 proxy (UDP ASSOCIATE)

```csharp Snippet:Socks5Udp
var client = new Socks5ProxyClient(new Socks5ProxyClientOptions {
    ProxyEndPoint = proxyEndPoint
});

// the local UDP socket that exchanges datagrams with the proxy
using var udp = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
var localUdpEndPoint = (IPEndPoint)udp.Client.LocalEndPoint!;

// the association lasts while this TCP control connection stays open, with nothing more sent on it
using var controlTcp = new TcpClient();
var relayEndPoint = await client.CreateUdpAssociateAsync(controlTcp, localUdpEndPoint, CancellationToken.None);

// wrap the payload in the SOCKS5 UDP header (10 bytes for IPv4, 22 for IPv6) and send it to the relay
var buffer = new byte[22 + payload.Length];
var length = Socks5ProxyClient.WriteUdpRequest(buffer, destination, payload);
await udp.SendAsync(buffer.AsMemory(0, length), relayEndPoint);

// receive the answer and unwrap it
var result = await udp.ReceiveAsync();
var from = Socks5ProxyClient.ParseUdpResponse(result.Buffer, out var answer);
```

### Run an HTTP proxy server

```csharp Snippet:HttpServer
using var server = new HttpProxyServer(new HttpProxyServerOptions {
    ListenEndPoint = new IPEndPoint(IPAddress.Loopback, 0), // 0: the system picks a free port
    Username = "user", // set a user name to require Basic authentication
    Password = "pass"
});

server.Start();
var proxyEndPoint = server.ListenerEndPoint;
```

Handles `CONNECT` tunnels (HTTPS traffic, IPv6 authorities like `[::1]:443` included) and forwards plain absolute-URI requests (`GET http://… HTTP/1.1`) with the client's headers preserved.

### Run an HTTPS proxy server (TLS between client and proxy)

```csharp Snippet:HttpsServer
using var server = new HttpsProxyServer(new HttpProxyServerOptions {
    ListenEndPoint = new IPEndPoint(IPAddress.Loopback, 0), // 0: the system picks a free port
    ServerCertificate = certificate // an X509Certificate2 with its private key
});

server.Start();
```

### Connect through an HTTP(S) proxy

```csharp Snippet:HttpConnect
var client = new HttpProxyClient(new HttpProxyClientOptions {
    ProxyEndPoint = proxyEndPoint,
    Username = "user", // Basic authentication, sent with every request
    Password = "pass",
    UseTls = false // true for an HTTPS proxy, with ProxyHost as the name on its certificate
});

using var tcp = new TcpClient();
await client.ConnectAsync(tcp, destinationHost, destinationPort, CancellationToken.None);

// Take the tunnel from the client: with UseTls, the connection's own stream would bypass TLS.
var stream = client.GetStream(tcp);
```

The client accepts any `2xx` CONNECT response and maps proxy errors (407, 429, 5xx, …) to a typed `ProxyClientException` with a meaningful `SocketError` code. Tunnels where the server speaks first (SMTP, SSH, …) work correctly — no bytes are lost after the handshake.

### Connect through a SOCKS4/4a proxy

```csharp Snippet:Socks4Connect
var client = new Socks4ProxyClient(new Socks4ProxyClientOptions {
    ProxyEndPoint = proxyEndPoint,
    UserName = null // the SOCKS4 user ID, when the proxy wants one
});

using var tcp = new TcpClient();
await client.ConnectAsync(tcp, destinationHost, destinationPort, CancellationToken.None); // a host name uses SOCKS4a

var stream = tcp.GetStream(); // the tunnel
```

## Command-line apps

The repo ships two small CLI utilities, handy for manual testing:

* **VpnHood.Net.Proxies.ServerApp** (`VhProxyServer`) — run an HTTP, HTTPS, or SOCKS5 proxy server, with optional auth and self-signed certificate generation.
* **VpnHood.Net.Proxies.ClientApp** (`VhProxyClient`) — connect through any supported proxy and exchange test data.

```bash
dotnet run --project samples/VpnHood.Net.Proxies.ServerApp -- socks5 --port 1080 --username user --password pass
dotnet run --project samples/VpnHood.Net.Proxies.ClientApp -- socks5 --proxy-port 1080 --username user --password pass
```

See [USAGE.md](https://github.com/vpnhood/VpnHood.Net.Proxies/blob/main/USAGE.md) for all commands and options.

## Error handling

Proxy-level failures throw `ProxyClientException`, which derives from `SocketException` and carries a mapped `SocketError` (e.g. `ConnectionRefused`, `HostUnreachable`, `AccessDenied`), so existing socket error handling keeps working. Authentication failures throw `UnauthorizedAccessException`; malformed peers throw `ProtocolViolationException`.

## Testing

Integration tests live in `tests/VpnHood.Net.Proxies.Tests` and run the real clients against the real servers over loopback — including UDP relays, TLS proxies, IPv6 CONNECT, pipelined requests, and injection attempts against the UDP relay:

```bash
dotnet test
```

## License

[LGPL-2.1](https://github.com/vpnhood/VpnHood.Net.Proxies/blob/main/LICENSE) © OmegaHood LLC — an independent library maintained by [VpnHood](https://github.com/vpnhood/vpnhood).
