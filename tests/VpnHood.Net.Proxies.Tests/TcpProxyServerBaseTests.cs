using System.Net;
using System.Net.Sockets;

namespace VpnHood.Net.Proxies.Tests;

[TestClass]
public class TcpProxyServerBaseTests
{
    // A server whose handler registers a cancellation callback that throws, as a derived server's code may
    private sealed class CallbackThrowingServer()
        : TcpProxyServerBase(new IPEndPoint(IPAddress.Loopback, 0), backlog: 16, maxConnections: 16, logger: null)
    {
        private readonly TaskCompletionSource _handlerStarted = new(TaskCreationOptions.RunContinuationsAsynchronously);

        public Task HandlerStarted => _handlerStarted.Task;

        protected override async Task HandleClientAsync(TcpClient client, CancellationToken cancellationToken)
        {
            using var registration = cancellationToken.Register(() =>
                throw new InvalidOperationException("The handler's cancellation callback fails."));
            _handlerStarted.TrySetResult();

            try {
                await Task.Delay(Timeout.Infinite, cancellationToken);
            }
            catch (OperationCanceledException) {
                // the server stops
            }
        }
    }

    // A server with one connection in its handler, so that a stop has the handler's callback to run
    private static async Task<CallbackThrowingServer> StartWithOneConnectionAsync(TcpClient client, CancellationToken cancellationToken)
    {
        var server = new CallbackThrowingServer();
        try {
            server.Start();
            await client.ConnectAsync(server.ListenerEndPoint, cancellationToken);
            await server.HandlerStarted.WaitAsync(cancellationToken);
            return server;
        }
        catch {
            server.Dispose();
            throw;
        }
    }

    // A closed listener refuses a connection; one left open would take it into a backlog nobody serves
    private static async Task AssertRefusesConnectionsAsync(IPEndPoint endPoint, CancellationToken cancellationToken)
    {
        using var client = new TcpClient();
        var exception = await Assert.ThrowsExactlyAsync<SocketException>(() =>
            client.ConnectAsync(endPoint, cancellationToken).AsTask());
        Assert.AreEqual(SocketError.ConnectionRefused, exception.SocketErrorCode);
    }

    [TestMethod]
    public async Task Stop_HandlerCancellationCallbackThrows_ListenerIsClosed()
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        using var client = new TcpClient();
        using var server = await StartWithOneConnectionAsync(client, cts.Token);
        var endPoint = server.ListenerEndPoint;

        server.Stop();

        Assert.IsFalse(server.IsStarted);
        await AssertRefusesConnectionsAsync(endPoint, cts.Token);
    }

    [TestMethod]
    public async Task Dispose_HandlerCancellationCallbackThrows_ListenerIsClosed()
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        using var client = new TcpClient();
        var server = await StartWithOneConnectionAsync(client, cts.Token);
        var endPoint = server.ListenerEndPoint;

        // a disposed server gets no second try at closing its listener
        server.Dispose();

        Assert.IsFalse(server.IsStarted);
        await AssertRefusesConnectionsAsync(endPoint, cts.Token);
    }

    [TestMethod]
    public async Task Stop_HandlerCancellationCallbackThrows_ServerStartsAgain()
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        using var client = new TcpClient();
        using var server = await StartWithOneConnectionAsync(client, cts.Token);

        server.Stop();
        server.Start();

        Assert.IsTrue(server.IsStarted);
        using var next = new TcpClient();
        await next.ConnectAsync(server.ListenerEndPoint, cts.Token);
    }
}
