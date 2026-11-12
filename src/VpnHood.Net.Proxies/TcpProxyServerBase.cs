using System.Net;
using System.Net.Sockets;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace VpnHood.Net.Proxies;

/// <summary>
/// Provides the listener, the connection limit and the lifetime of a TCP proxy server; a derived class serves
/// each connection.
/// </summary>
/// <remarks>
/// The server accepts connections from <see cref="Start"/> until <see cref="Stop"/> or <see cref="Dispose()"/>,
/// and passes each to <see cref="HandleClientAsync"/> on its own task. It can start again after it stops, but
/// not after it is disposed. <see cref="Start"/>, <see cref="Stop"/> and <see cref="Dispose()"/> may be called
/// from any thread.
/// </remarks>
/// <param name="listenEndPoint">The address and port to listen on. Port 0 lets the system choose one.</param>
/// <param name="backlog">The maximum number of pending connections the listener queues.</param>
/// <param name="maxConnections">
/// The maximum number of connections served at once; a connection beyond it is accepted and closed at once.
/// </param>
/// <param name="logger">The logger for the server's events, or <see langword="null"/> for none.</param>
/// <exception cref="ArgumentNullException"><paramref name="listenEndPoint"/> is <see langword="null"/>.</exception>
/// <exception cref="ArgumentOutOfRangeException"><paramref name="backlog"/> or <paramref name="maxConnections"/> is zero or negative.</exception>
public abstract class TcpProxyServerBase(
    IPEndPoint listenEndPoint,
    int backlog,
    int maxConnections,
    ILogger? logger
) : IDisposable
{
    /// <summary>
    /// The logger the server writes to; a logger that discards everything when none was given.
    /// </summary>
    protected readonly ILogger Logger = logger ?? NullLogger.Instance;
    private readonly Lock _startStopLock = new();
    private CancellationTokenSource? _serverCts;
    private bool _disposed;
    private int _connectionCount;
    private readonly TcpListener _listener = new(listenEndPoint);

    // validated copies of the primary-constructor parameters; MaxConnections = 0 would
    // otherwise silently reject every connection
    private readonly int _backlog = backlog > 0
        ? backlog
        : throw new ArgumentOutOfRangeException(nameof(backlog), backlog, "Backlog must be positive.");
    private readonly int _maxConnections = maxConnections > 0
        ? maxConnections
        : throw new ArgumentOutOfRangeException(nameof(maxConnections), maxConnections, "MaxConnections must be positive.");

    /// <summary>
    /// Gets the address and port the server listens on. Once the server has started, it carries the port the
    /// system chose when the configured port is 0.
    /// </summary>
    public IPEndPoint ListenerEndPoint => (IPEndPoint)_listener.LocalEndpoint;

    /// <summary>
    /// Gets a value indicating whether the server is listening.
    /// </summary>
    public bool IsStarted => _serverCts is not null;

    /// <summary>
    /// Gets the number of client connections being served now.
    /// </summary>
    public int ActiveConnectionCount => Volatile.Read(ref _connectionCount);

    /// <summary>
    /// Serves one client connection.
    /// </summary>
    /// <remarks>
    /// It runs on its own task for each accepted connection. When the returned task completes, the base class
    /// disposes <paramref name="client"/>, and it logs any exception the task throws.
    /// </remarks>
    /// <param name="client">The accepted connection.</param>
    /// <param name="cancellationToken">The token that is canceled when the server stops.</param>
    /// <returns>A task that represents the asynchronous operation. It completes when the connection is done.</returns>
    protected abstract Task HandleClientAsync(TcpClient client, CancellationToken cancellationToken);

    /// <summary>
    /// Starts listening for connections. Calling it on a server that is listening does nothing.
    /// </summary>
    /// <exception cref="ObjectDisposedException">The server is disposed.</exception>
    /// <exception cref="SocketException">The listener cannot use its address and port, for example because another socket holds them.</exception>
    public void Start()
    {
        lock (_startStopLock)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            if (_serverCts is not null) return;

            _listener.Start(_backlog);
            _serverCts = new CancellationTokenSource();
            _ = ListenAsync(_serverCts.Token);
        }

        Logger.LogInformation("{ServerType} started on {EndPoint}", GetType().Name, ListenerEndPoint);
    }

    /// <summary>
    /// Stops listening and cancels the token of every connection being served, without waiting for them to end.
    /// Calling it on a server that is not listening does nothing.
    /// </summary>
    public void Stop()
    {
        bool stopped;
        lock (_startStopLock)
        {
            stopped = StopCore();
        }

        if (stopped)
            Logger.LogInformation("{ServerType} stopped", GetType().Name);
    }

    // The whole stop transition runs under _startStopLock (callers hold it): if any part of
    // it (especially _listener.Stop) ran outside, a concurrent Start() could install a fresh
    // listener that this call would then stop, leaving IsStarted true with a dead listener.
    private bool StopCore()
    {
        var serverCts = _serverCts;
        if (serverCts is null) return false;
        _serverCts = null;

        serverCts.Cancel();
        serverCts.Dispose();
        _listener.Stop();
        return true;
    }

    /// <summary>
    /// Starts the server, keeps it running until <paramref name="cancellationToken"/> is canceled, then stops it.
    /// </summary>
    /// <param name="cancellationToken">
    /// The token that stops the server. With the default, which is never canceled, the task never completes,
    /// even after <see cref="Stop"/> or <see cref="Dispose()"/>.
    /// </param>
    /// <returns>
    /// A task that represents the asynchronous operation. It completes when the server has stopped, and does
    /// not fault when the token is canceled.
    /// </returns>
    /// <exception cref="ObjectDisposedException">The server is disposed.</exception>
    /// <exception cref="SocketException">The listener cannot use its address and port, for example because another socket holds them.</exception>
    public async Task RunAsync(CancellationToken cancellationToken = default)
    {
        Start();
        try
        {
            await Task.Delay(Timeout.Infinite, cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            // graceful shutdown
        }
        finally
        {
            Stop();
        }
    }

    private async Task ListenAsync(CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            try
            {
                var client = await _listener.AcceptTcpClientAsync(cancellationToken).ConfigureAwait(false);

                // Hard cap on concurrent connections. Each connection costs buffers, tasks and
                // (for TLS) SslStream internals; without a cap a burst of connections can
                // exhaust a constrained host (e.g. an iOS Network Extension) no matter how
                // cheap each one is.
                if (Interlocked.Increment(ref _connectionCount) > _maxConnections)
                {
                    Interlocked.Decrement(ref _connectionCount);

                    // using guarantees disposal even if logging (endpoint read) throws;
                    // otherwise a reset connection would leak the socket
                    using (client)
                    {
                        Logger.LogWarning("Connection limit ({MaxConnections}) reached; rejecting {ClientEndpoint}",
                            _maxConnections, TryGetRemoteEndPoint(client)?.ToString() ?? "unknown");
                    }
                    continue;
                }

                _ = RunClientAsync(client, cancellationToken);
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (ObjectDisposedException)
            {
                break;
            }
            catch (Exception exception)
            {
                Logger.LogError(exception, "Error accepting client connection");
            }
        }
    }

    private async Task RunClientAsync(TcpClient client, CancellationToken cancellationToken)
    {
        // The base owns disposal so a handler that throws before reaching its own using
        // statement cannot leak the socket. TcpClient.Dispose is idempotent, so handlers
        // disposing it themselves too is fine.
        using var clientToDispose = client;
        try
        {
            await HandleClientAsync(client, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception exception)
        {
            Logger.LogError(exception, "Unhandled error in client handler");
        }
        finally
        {
            Interlocked.Decrement(ref _connectionCount);
        }
    }

    /// <summary>
    /// Gets a client's remote address and port, or <see langword="null"/> when they cannot be read, as on a
    /// connection that was already reset.
    /// </summary>
    /// <param name="client">The client connection.</param>
    /// <returns>The remote endpoint, or <see langword="null"/>.</returns>
    protected static IPEndPoint? TryGetRemoteEndPoint(TcpClient client)
    {
        try
        {
            return client.Client.RemoteEndPoint as IPEndPoint;
        }
        catch
        {
            return null;
        }
    }

    /// <summary>
    /// Stops the server and releases its listener.
    /// </summary>
    /// <param name="disposing">
    /// <see langword="true"/> when called from <see cref="Dispose()"/>; <see langword="false"/> when called from
    /// a finalizer, in which case nothing is released.
    /// </param>
    protected virtual void Dispose(bool disposing)
    {
        if (disposing)
        {
            bool stopped;

            // stop and mark disposed in ONE lock acquisition: if the lock were released
            // between the two, a concurrent Start() could slip in, restart the listener and
            // install a new CTS that this disposal would then orphan
            lock (_startStopLock)
            {
                if (_disposed) return;
                _disposed = true;
                stopped = StopCore();
                _listener.Dispose();
            }

            if (stopped)
                Logger.LogInformation("{ServerType} stopped", GetType().Name);
        }
    }

    /// <summary>
    /// Stops the server and releases its listener. The server cannot start again.
    /// </summary>
    public void Dispose()
    {
        Dispose(true);
        GC.SuppressFinalize(this);
    }
}
