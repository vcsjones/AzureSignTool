using System.Security.Cryptography.X509Certificates;

namespace AzureSign.Opc
{
    public interface IX509CertificateProvider : IDisposable
    {
        Task<X509Certificate2> GetCertificateAsync(CancellationToken ct);
    }
}
