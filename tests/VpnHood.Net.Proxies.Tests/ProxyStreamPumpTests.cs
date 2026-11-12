using System.Net.Security;
using VpnHood.Net.Proxies.Tests.TestHelpers;

namespace VpnHood.Net.Proxies.Tests;

[TestClass]
public class ProxyStreamPumpTests
{
    [TestMethod]
    public async Task Pump_TlsClientReadsNothing_TunnelEndsWithHalfCloseTimeout()
    {
        // a TLS session between the proxy and its client, over a connection whose flow the test controls:
        // over a socket, a send that blocks at just the right byte cannot be arranged
        using var connection = new InMemoryConnection();
        using var certificate = TestCertificates.CreateSelfSigned();
        await using var proxyTls = new SslStream(connection.First);
        await using var clientTls = new SslStream(connection.Second);
        await Task.WhenAll(
            proxyTls.AuthenticateAsServerAsync(certificate),
            clientTls.AuthenticateAsClientAsync(new SslClientAuthenticationOptions {
                TargetHost = "127.0.0.1",
                RemoteCertificateValidationCallback = (_, _, _, _) => true
            }));

        // from here on the client reads nothing, so nothing the proxy sends it gets out, its TLS close_notify
        // included
        connection.First.BlockWrites();

        // the destination ends its side at once, which leaves the proxy with that end to pass on to the client
        using var destination = new MemoryStream();
        var pump = ProxyStreamPump.PumpStreamsAsync(proxyTls, destination,
            halfCloseTimeout: TimeSpan.FromMilliseconds(300), CancellationToken.None);

        // the half-close timeout covers the close_notify too: a client that reads nothing must not hold the
        // tunnel for as long as it likes
        await pump.WaitAsync(TimeSpan.FromSeconds(10));
    }

    [TestMethod]
    public async Task Pump_TlsClientReads_EndIsPassedOn_AndItsDataStillArrives()
    {
        using var connection = new InMemoryConnection();
        using var certificate = TestCertificates.CreateSelfSigned();
        await using var proxyTls = new SslStream(connection.First);
        await using var clientTls = new SslStream(connection.Second);
        await Task.WhenAll(
            proxyTls.AuthenticateAsServerAsync(certificate),
            clientTls.AuthenticateAsClientAsync(new SslClientAuthenticationOptions {
                TargetHost = "127.0.0.1",
                RemoteCertificateValidationCallback = (_, _, _, _) => true
            }));

        // the destination has one answer, then ends its side; the client keeps its own side open and silent
        var answer = "the destination's last words"u8.ToArray();
        using var destination = new MemoryStream();
        destination.Write(answer);
        destination.Position = 0;
        var pump = ProxyStreamPump.PumpStreamsAsync(proxyTls, destination,
            halfCloseTimeout: TimeSpan.FromMilliseconds(500), CancellationToken.None);

        // the client gets the answer, then the clean end of the TLS stream
        var received = new byte[answer.Length];
        await clientTls.ReadExactlyAsync(received).AsTask().WaitAsync(TimeSpan.FromSeconds(10));
        CollectionAssert.AreEqual(answer, received);
        Assert.AreEqual(0, await clientTls.ReadAsync(new byte[1]).AsTask().WaitAsync(TimeSpan.FromSeconds(10)));

        // the client stays silent, so the tunnel ends with the half-close timeout
        await pump.WaitAsync(TimeSpan.FromSeconds(10));
    }
}
