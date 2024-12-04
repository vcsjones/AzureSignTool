using System.Security.Cryptography;

namespace AzureSign.Opc
{
    public interface IRsaCryptoServiceProvider : IDisposable
    {
        Task<RSA> GetRsaAsync(CancellationToken ct);
    }
}
