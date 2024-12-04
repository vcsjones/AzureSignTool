using System.Security.Cryptography;

namespace AzureSign.Opc.Tests;

public class RsaCryptoServiceProviderTest
{
    [Fact]
    public async Task GetRsaAsync_returns_the_RSA_instance_given_during_construction()
    {
        var ct = TestContext.Current.CancellationToken;

        using var expectedRsa = RSA.Create(keySizeInBits: 2048);
        var provider = new RsaCryptoServiceProvider(expectedRsa);
        var rsa = await provider.GetRsaAsync(ct);

        rsa.Should().BeSameAs(expectedRsa);
    }
}
