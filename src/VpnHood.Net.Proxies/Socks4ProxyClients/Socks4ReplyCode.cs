namespace VpnHood.Net.Proxies.Socks4ProxyClients;

/// <summary>
/// Specifies the result code of a SOCKS4 reply.
/// </summary>
// ReSharper disable IdentifierTypo
public enum Socks4ReplyCode : byte
{
    /// <summary>The request was granted.</summary>
    RequestGranted = 0x5A,

    /// <summary>The request was rejected or failed.</summary>
    RequestRejectedOrFailed = 0x5B,

    /// <summary>The request was rejected because the server could not reach the client's identd (RFC 1413).</summary>
    CannotConnectToIdentd = 0x5C,

    /// <summary>The request was rejected because the client's identd reported another user ID than the request.</summary>
    DifferingUserId = 0x5D
}
