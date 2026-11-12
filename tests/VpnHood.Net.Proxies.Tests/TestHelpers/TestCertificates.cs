using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace VpnHood.Net.Proxies.Tests.TestHelpers;

internal static class TestCertificates
{
    /// <summary>
    /// Creates a self-signed certificate for 127.0.0.1, with its private key. The caller disposes it.
    /// </summary>
    public static X509Certificate2 CreateSelfSigned()
    {
        using var rsa = RSA.Create(2048);
        var request = new CertificateRequest("CN=127.0.0.1", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var sanBuilder = new SubjectAlternativeNameBuilder();
        sanBuilder.AddIpAddress(IPAddress.Loopback);
        request.CertificateExtensions.Add(sanBuilder.Build());
        using var cert = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(30));

        // re-import so the ephemeral private key is usable by SslStream on Windows
        return X509CertificateLoader.LoadPkcs12(cert.Export(X509ContentType.Pfx), password: null);
    }
}
