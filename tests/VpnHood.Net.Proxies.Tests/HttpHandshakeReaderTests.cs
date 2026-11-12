using System.Net;
using System.Text;
using VpnHood.Net.Proxies.HttpProxyServers;
using VpnHood.Net.Proxies.Tests.TestHelpers;

namespace VpnHood.Net.Proxies.Tests;

// The reader's limits, with each read's end chosen by the test: over a socket, where a read ends is chance.
[TestClass]
public class HttpHandshakeReaderTests
{
    private const string RequestLine = "GET / HTTP/1.1";

    // A request line and header lines of the given length in bytes, the blank line that ends them included
    private static byte[] BuildRequestHead(int totalLength)
    {
        const int lineLength = 5000;
        const int blankLineLength = 2;
        var builder = new StringBuilder(RequestLine + "\r\n");
        var index = 0;
        while (totalLength - builder.Length - blankLineLength >= lineLength)
            AppendHeaderLine(builder, index++, lineLength);

        var rest = totalLength - builder.Length - blankLineLength;
        if (rest > 0)
            AppendHeaderLine(builder, index, rest);

        builder.Append("\r\n");
        Assert.AreEqual(totalLength, builder.Length);
        return Encoding.ASCII.GetBytes(builder.ToString());
    }

    // lineLength counts the whole line, its CRLF included
    private static void AppendHeaderLine(StringBuilder builder, int index, int lineLength)
    {
        var name = $"X-{index}: ";
        builder.Append(name).Append('a', lineLength - name.Length - 2).Append("\r\n");
    }

    [TestMethod]
    public async Task ReadLine_LineOfMaximumLength_ReadEndsAfterItsCr_IsAccepted()
    {
        // the line end is split between two reads: whether the line passes must not depend on that
        var line = new string('a', HttpHandshakeReader.MaxLineLength);
        using var reader = new HttpHandshakeReader(new ChunkedStream(
            Encoding.ASCII.GetBytes(line + "\r"),
            "\n"u8.ToArray()));

        Assert.AreEqual(line, await reader.ReadLineAsync(CancellationToken.None));
    }

    [TestMethod]
    public async Task ReadLine_LineOfMaximumLength_InOneRead_IsAccepted()
    {
        var line = new string('a', HttpHandshakeReader.MaxLineLength);
        using var reader = new HttpHandshakeReader(new ChunkedStream(Encoding.ASCII.GetBytes(line + "\r\n")));

        Assert.AreEqual(line, await reader.ReadLineAsync(CancellationToken.None));
    }

    [TestMethod]
    public async Task ReadLine_LineOverMaximumLength_IsRefused()
    {
        var tooLong = new string('a', HttpHandshakeReader.MaxLineLength + 1);

        // its end in the same read
        using var oneRead = new HttpHandshakeReader(new ChunkedStream(Encoding.ASCII.GetBytes(tooLong + "\r\n")));
        await Assert.ThrowsExactlyAsync<ProtocolViolationException>(() => oneRead.ReadLineAsync(CancellationToken.None));

        // its end in the next read, which the reader does not wait for
        using var twoReads = new HttpHandshakeReader(new ChunkedStream(
            Encoding.ASCII.GetBytes(tooLong),
            "\r\n"u8.ToArray()));
        await Assert.ThrowsExactlyAsync<ProtocolViolationException>(() => twoReads.ReadLineAsync(CancellationToken.None));

        // a CR that no LF follows is content, and makes this line one byte too long
        var atLimit = new string('a', HttpHandshakeReader.MaxLineLength);
        using var bareCr = new HttpHandshakeReader(new ChunkedStream(
            Encoding.ASCII.GetBytes(atLimit + "\r"),
            "x\r\n"u8.ToArray()));
        await Assert.ThrowsExactlyAsync<ProtocolViolationException>(() => bareCr.ReadLineAsync(CancellationToken.None));
    }

    [TestMethod]
    public async Task ReadHeaders_TotalAtTheLimit_IsAccepted()
    {
        var head = BuildRequestHead(HttpHandshakeReader.MaxTotalHeaderBytes);
        using var reader = new HttpHandshakeReader(new ChunkedStream(head));

        Assert.AreEqual(RequestLine, await reader.ReadLineAsync(CancellationToken.None));
        var headers = await reader.ReadHeadersAsync(CancellationToken.None);
        Assert.AreEqual(7, headers.Count);
    }

    [TestMethod]
    public async Task ReadHeaders_TotalOverTheLimit_IsRefused()
    {
        var head = BuildRequestHead(HttpHandshakeReader.MaxTotalHeaderBytes + 1);
        using var reader = new HttpHandshakeReader(new ChunkedStream(head));

        Assert.AreEqual(RequestLine, await reader.ReadLineAsync(CancellationToken.None));
        await Assert.ThrowsExactlyAsync<ProtocolViolationException>(() => reader.ReadHeadersAsync(CancellationToken.None));
    }

    [TestMethod]
    public async Task ReadHeaders_BytesBehindTheHeaders_DoNotCountTowardTheirLimit()
    {
        // the headers are within their limit; the 20,000 bytes behind them (a body, tunnel data) are the
        // caller's, however many of them a read brings in along with the headers' end
        var head = BuildRequestHead(HttpHandshakeReader.MaxTotalHeaderBytes - 68);
        var behind = new byte[20_000];
        Array.Fill(behind, (byte)'b');
        using var reader = new HttpHandshakeReader(new ChunkedStream([.. head, .. behind]));

        Assert.AreEqual(RequestLine, await reader.ReadLineAsync(CancellationToken.None));
        var headers = await reader.ReadHeadersAsync(CancellationToken.None);
        Assert.AreEqual(7, headers.Count);

        // what a read took past the headers is handed back, not lost
        var remainder = reader.DetachRemainder();
        Assert.IsTrue(behind.AsSpan().StartsWith(remainder));
    }

    [TestMethod]
    public async Task ReadHeaders_RepeatedName_KeepsEveryLineInOrder()
    {
        var head = "X-Tag: one\r\nAccept: text/html\r\nx-tag:  two \r\nno colon here\r\nX-Tag: three\r\n\r\n"u8.ToArray();
        using var reader = new HttpHandshakeReader(new ChunkedStream(head));

        var headers = await reader.ReadHeadersAsync(CancellationToken.None);

        CollectionAssert.AreEqual(
            new[] {
                new HttpHeader("X-Tag", "one"),
                new HttpHeader("Accept", "text/html"),
                new HttpHeader("x-tag", "two"),
                new HttpHeader("X-Tag", "three")
            },
            headers.ToArray());
    }

    [TestMethod]
    public async Task ReadHeaders_LineCountLimit_CountsRepeatedNamesToo()
    {
        var atLimit = Encoding.ASCII.GetBytes(string.Concat(Enumerable.Repeat("X: v\r\n", HttpHandshakeReader.MaxHeaderCount)) + "\r\n");
        using var accepted = new HttpHandshakeReader(new ChunkedStream(atLimit));
        Assert.AreEqual(HttpHandshakeReader.MaxHeaderCount, (await accepted.ReadHeadersAsync(CancellationToken.None)).Count);

        var overLimit = Encoding.ASCII.GetBytes(string.Concat(Enumerable.Repeat("X: v\r\n", HttpHandshakeReader.MaxHeaderCount + 1)) + "\r\n");
        using var refused = new HttpHandshakeReader(new ChunkedStream(overLimit));
        await Assert.ThrowsExactlyAsync<ProtocolViolationException>(() => refused.ReadHeadersAsync(CancellationToken.None));
    }
}
