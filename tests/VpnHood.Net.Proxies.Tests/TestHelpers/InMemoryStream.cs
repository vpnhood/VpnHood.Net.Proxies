using System.Threading.Channels;

namespace VpnHood.Net.Proxies.Tests.TestHelpers;

/// <summary>
/// One end of an <see cref="InMemoryConnection"/>: it reads what the other end writes. Its writes can be made
/// to wait, as they do on a connection whose peer reads nothing.
/// </summary>
internal sealed class InMemoryStream(ChannelReader<byte[]> incoming, ChannelWriter<byte[]> outgoing) : Stream
{
    private readonly TaskCompletionSource _disposed = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private byte[] _current = [];
    private int _currentOffset;
    private volatile bool _writesBlocked;

    public override bool CanRead => true;
    public override bool CanSeek => false;
    public override bool CanWrite => true;
    public override long Length => throw new NotSupportedException();

    public override long Position {
        get => throw new NotSupportedException();
        set => throw new NotSupportedException();
    }

    /// <summary>
    /// Makes every write from now on wait until the stream is disposed, then fail.
    /// </summary>
    public void BlockWrites() => _writesBlocked = true;

    // A read into an empty buffer waits for data and takes none, as SslStream expects of its inner stream
    public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
    {
        if (_currentOffset == _current.Length) {
            if (!await incoming.WaitToReadAsync(cancellationToken) || !incoming.TryRead(out var next))
                return 0;

            _current = next;
            _currentOffset = 0;
        }

        var count = Math.Min(buffer.Length, _current.Length - _currentOffset);
        _current.AsMemory(_currentOffset, count).CopyTo(buffer);
        _currentOffset += count;
        return count;
    }

    public override async ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
    {
        if (_writesBlocked) {
            await _disposed.Task.WaitAsync(cancellationToken);
            throw new ObjectDisposedException(nameof(InMemoryStream));
        }

        await outgoing.WriteAsync(buffer.ToArray(), cancellationToken);
    }

    public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) =>
        ReadAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();

    public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) =>
        WriteAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();

    public override Task FlushAsync(CancellationToken cancellationToken) => Task.CompletedTask;

    public override void Flush()
    {
    }

    public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
    public override void SetLength(long value) => throw new NotSupportedException();

    protected override void Dispose(bool disposing)
    {
        if (disposing) {
            outgoing.TryComplete();
            _disposed.TrySetResult();
        }

        base.Dispose(disposing);
    }
}
