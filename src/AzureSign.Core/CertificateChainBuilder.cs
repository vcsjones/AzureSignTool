using System;
using System.Security.Cryptography.X509Certificates;

namespace AzureSign.Core
{
    internal static class CertificateChainBuilder
    {
        public static X509Chain Build(X509Certificate2 certificate, X509Certificate2Collection? additionalCertificates)
        {
            X509Chain chain = new X509Chain();

            try
            {
                if (additionalCertificates is not null)
                {
                    chain.ChainPolicy.ExtraStore.AddRange(additionalCertificates);
                }

                //We don't care about the trustworthiness of the cert. We just want a chain to sign with.
                chain.ChainPolicy.VerificationFlags = X509VerificationFlags.AllFlags;

                if (!chain.Build(certificate))
                {
                    throw new InvalidOperationException("Failed to build chain for certificate.");
                }

                return chain;
            }
            catch
            {
                chain.Dispose();
                throw;
            }
        }
    }
}
