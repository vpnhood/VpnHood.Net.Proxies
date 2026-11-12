using System.Threading.Channels;

namespace VpnHood.Net.Proxies.Tests.TestHelpers;

/// <summary>
/// Two connected in-memory streams: what one writes, the other reads.
/// </summary>
internal sealed class InMemoryConnection : IDisposable
{
    public InMemoryStream First { get; }
    public InMemoryStream Second { get; }

    public InMemoryConnection()
    {
        var firstToSecond = Channel.CreateUnbounded<byte[]>();
        var secondToFirst = Channel.CreateUnbounded<byte[]>();
        First = new InMemoryStream(secondToFirst.Reader, firstToSecond.Writer);
        Second = new InMemoryStream(firstToSecond.Reader, secondToFirst.Writer);
    }

    public void Dispose()
    {
        First.Dispose();
        Second.Dispose();
    }
}
