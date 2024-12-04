using System.Security.Cryptography;
using Azure.Security.KeyVault.Keys.Cryptography;

namespace AzureSign.Opc;

public sealed class RsaCryptoServiceProvider : IRsaCryptoServiceProvider
{
    private readonly CryptographyClient? _cryptographyClient;
    private readonly RSA? _injectedRsa;
    private RSA? _keyVaultRsa;

    public RsaCryptoServiceProvider(RSA rsa)
    {
        _injectedRsa = rsa;
    }

    public RsaCryptoServiceProvider(CryptographyClient cryptographyClient)
    {
        _cryptographyClient = cryptographyClient;
    }

    public async Task<RSA> GetRsaAsync(CancellationToken ct)
    {
        if (_injectedRsa is not null)
        {
            return _injectedRsa;
        }
        if (_cryptographyClient is null)
        {
            throw new InvalidOperationException("CryptographyClient or RSA instance not provided.");
        }
        return (_keyVaultRsa ??= await _cryptographyClient.CreateRSAAsync(ct));
    }

    public void Dispose()
    {
        _keyVaultRsa?.Dispose();
    }
}
