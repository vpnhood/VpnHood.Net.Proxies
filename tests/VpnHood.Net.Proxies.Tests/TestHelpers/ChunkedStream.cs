namespace VpnHood.Net.Proxies.Tests.TestHelpers;

/// <summary>
/// A read-only stream that gives out prepared chunks, at most one for each read, then the end of the
/// stream: a test chooses where each read ends.
/// </summary>
internal sealed class ChunkedStream(params byte[][] chunks) : Stream
{
    private int _chunkIndex;
    private int _chunkOffset;

    public override bool CanRead => true;
    public override bool CanSeek => false;
    public override bool CanWrite => false;
    public override long Length => throw new NotSupportedException();

    public override long Position {
        get => throw new NotSupportedException();
        set => throw new NotSupportedException();
    }

    public override int Read(Span<byte> buffer)
    {
        if (_chunkIndex == chunks.Length)
            return 0;

        var chunk = chunks[_chunkIndex];
        var count = Math.Min(buffer.Length, chunk.Length - _chunkOffset);
        chunk.AsSpan(_chunkOffset, count).CopyTo(buffer);
        _chunkOffset += count;
        if (_chunkOffset == chunk.Length) {
            _chunkIndex++;
            _chunkOffset = 0;
        }

        return count;
    }

    public override int Read(byte[] buffer, int offset, int count) =>
        Read(buffer.AsSpan(offset, count));

    public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default) =>
        ValueTask.FromResult(Read(buffer.Span));

    public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) =>
        Task.FromResult(Read(buffer.AsSpan(offset, count)));

    public override void Flush()
    {
    }

    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
    public override void SetLength(long value) => throw new NotSupportedException();
    public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
}
