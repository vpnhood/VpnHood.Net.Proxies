using System.Net;
using System.Net.Sockets;
using System.Text;
using VpnHood.Net.Proxies.Socks5Proxy;
using VpnHood.Net.Proxies.Socks5ProxyServers;
using VpnHood.Net.Proxies.Tests.TestHelpers;

namespace VpnHood.Net.Proxies.Tests;

// Speaks raw SOCKS5 to the server, for what the library's own client never sends.
[TestClass]
public class Socks5ProxyServerTests
{
    private static Socks5ProxyServer StartSocks5Proxy(TimeSpan? handshakeTimeout = null, TimeSpan? hostConnectionTimeout = null)
    {
        var server = new Socks5ProxyServer(new Socks5ProxyServerOptions {
            ListenEndPoint = new IPEndPoint(IPAddress.Loopback, 0),
            HandshakeTimeout = handshakeTimeout ?? TimeSpan.FromSeconds(15),
            HostConnectionTimeout = hostConnectionTimeout ?? TimeSpan.FromSeconds(30)
        });
        server.Start();
        return server;
    }

    // Connects and completes the method negotiation with "no authentication"; the request is the caller's
    private static async Task<TcpClient> ConnectAndNegotiateAsync(IPEndPoint proxyEndPoint, CancellationToken cancellationToken)
    {
        var tcp = new TcpClient();
        try {
            await tcp.ConnectAsync(proxyEndPoint, cancellationToken);
            var stream = tcp.GetStream();
            await stream.WriteAsync(new byte[] { 5, 1, 0 }, cancellationToken);
            var method = new byte[2];
            await stream.ReadExactlyAsync(method, cancellationToken);
            CollectionAssert.AreEqual(new byte[] { 5, 0 }, method);
            return tcp;
        }
        catch {
            tcp.Dispose();
            throw;
        }
    }

    // Reads the reply to a request that failed: VER, REP, RSV, ATYP, an IPv4 address and a port, all zeros
    private static async Task<Socks5CommandReply> ReadFailureReplyAsync(Stream stream, CancellationToken cancellationToken)
    {
        var reply = new byte[10];
        await stream.ReadExactlyAsync(reply, cancellationToken);
        Assert.AreEqual(5, reply[0], "the reply's SOCKS version");
        Assert.AreEqual((byte)Socks5AddressType.IpV4, reply[3], "the reply's address type");
        return (Socks5CommandReply)reply[1];
    }

    // 0 when the server closed the connection; a reset counts as closed too
    private static async Task<int> ReadUntilClosedAsync(Stream stream, CancellationToken cancellationToken)
    {
        try {
            return await stream.ReadAsync(new byte[16], cancellationToken);
        }
        catch (IOException) {
            return 0;
        }
    }

    [TestMethod]
    public async Task Socks5Server_NoRequestAfterNegotiation_ClosedWhenHandshakeTimeoutEnds()
    {
        using var server = StartSocks5Proxy(handshakeTimeout: TimeSpan.FromSeconds(1));
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));

        // the client negotiates, then asks for nothing: it must not hold its connection for as long as it likes
        using var tcp = await ConnectAndNegotiateAsync(server.ListenerEndPoint, cts.Token);

        Assert.AreEqual(0, await ReadUntilClosedAsync(tcp.GetStream(), cts.Token),
            "the server should close a connection whose request does not come in time");
    }

    [TestMethod]
    public async Task Socks5Server_RequestCutShort_ClosedWhenHandshakeTimeoutEnds()
    {
        using var server = StartSocks5Proxy(handshakeTimeout: TimeSpan.FromSeconds(1));
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        using var tcp = await ConnectAndNegotiateAsync(server.ListenerEndPoint, cts.Token);
        var stream = tcp.GetStream();

        // CONNECT to an IPv4 address, with only two of the address's four bytes and no port
        await stream.WriteAsync(new byte[] { 5, (byte)Socks5Command.Connect, 0, (byte)Socks5AddressType.IpV4, 127, 0 }, cts.Token);

        Assert.AreEqual(0, await ReadUntilClosedAsync(stream, cts.Token),
            "the server should close a connection whose request stays incomplete");
    }

    [TestMethod]
    public async Task Socks5Server_RequestWithinHandshakeTimeout_IsServed()
    {
        // the request's own deadline must not cut a tunnel that is already open
        using var echo = new EchoServer(IPAddress.Loopback);
        using var server = StartSocks5Proxy(handshakeTimeout: TimeSpan.FromSeconds(1));
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        using var tcp = await ConnectAndNegotiateAsync(server.ListenerEndPoint, cts.Token);
        var stream = tcp.GetStream();

        var address = echo.EndPoint.Address.GetAddressBytes();
        var port = echo.EndPoint.Port;
        await stream.WriteAsync(new byte[] {
            5, (byte)Socks5Command.Connect, 0, (byte)Socks5AddressType.IpV4,
            address[0], address[1], address[2], address[3], (byte)(port >> 8), (byte)port
        }, cts.Token);

        var reply = new byte[10];
        await stream.ReadExactlyAsync(reply, cts.Token);
        Assert.AreEqual((byte)Socks5CommandReply.Succeeded, reply[1]);

        // well past the handshake timeout, the tunnel still carries data
        await Task.Delay(TimeSpan.FromSeconds(2), cts.Token);
        var payload = "still open"u8.ToArray();
        await stream.WriteAsync(payload, cts.Token);
        var echoed = new byte[payload.Length];
        await stream.ReadExactlyAsync(echoed, cts.Token);
        CollectionAssert.AreEqual(payload, echoed);
    }

    [TestMethod]
    public async Task Socks5Server_UnknownAddressType_RepliesAddressTypeNotSupported()
    {
        using var server = StartSocks5Proxy();
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        using var tcp = await ConnectAndNegotiateAsync(server.ListenerEndPoint, cts.Token);
        var stream = tcp.GetStream();

        // address type 9 does not exist; nothing follows it, so the server has nothing left unread when it closes
        await stream.WriteAsync(new byte[] { 5, (byte)Socks5Command.Connect, 0, 9 }, cts.Token);

        Assert.AreEqual(Socks5CommandReply.AddressTypeNotSupported, await ReadFailureReplyAsync(stream, cts.Token));
        Assert.AreEqual(0, await ReadUntilClosedAsync(stream, cts.Token));
    }

    [TestMethod]
    public async Task Socks5Server_DomainThatCannotBeLookedUp_GetsFailureReply()
    {
        using var server = StartSocks5Proxy(hostConnectionTimeout: TimeSpan.FromSeconds(5));
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        using var tcp = await ConnectAndNegotiateAsync(server.ListenerEndPoint, cts.Token);
        var stream = tcp.GetStream();

        // ".invalid" never resolves (RFC 2606)
        var name = Encoding.ASCII.GetBytes("no-such-host.invalid");
        byte[] request = [5, (byte)Socks5Command.Connect, 0, (byte)Socks5AddressType.DomainName, (byte)name.Length, .. name, 0, 80];
        await stream.WriteAsync(request, cts.Token);

        // HostUnreachable where the lookup fails, as it should; TtlExpired where it gets no answer in time. Either
        // way the client hears why, where the server used to close without a word.
        var reply = await ReadFailureReplyAsync(stream, cts.Token);
        Assert.AreNotEqual(Socks5CommandReply.Succeeded, reply);
    }

    [TestMethod]
    public async Task Socks5Server_Bind_RepliesCommandNotSupported()
    {
        using var server = StartSocks5Proxy();
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        using var tcp = await ConnectAndNegotiateAsync(server.ListenerEndPoint, cts.Token);
        var stream = tcp.GetStream();

        await stream.WriteAsync(new byte[] { 5, (byte)Socks5Command.Bind, 0, (byte)Socks5AddressType.IpV4, 127, 0, 0, 1, 0, 80 }, cts.Token);

        Assert.AreEqual(Socks5CommandReply.CommandNotSupported, await ReadFailureReplyAsync(stream, cts.Token));
    }
}
