using Microsoft.Azure.KeyVault;
using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;



namespace OpenSignTool
{

    /// <summary>
    /// A signing context used for signing packages with Azure Key Vault Keys.
    /// </summary>
    public class KeyVaultSigningContext
    {
        private readonly AzureKeyVaultMaterializedConfiguration _configuration;

        /// <summary>
        /// Creates a new siging context.
        /// </summary>
        public KeyVaultSigningContext(AzureKeyVaultMaterializedConfiguration configuration)
        {
            ContextCreationTime = DateTimeOffset.Now;
            _configuration = configuration;
        }

        /// <summary>
        /// Gets the date and time that this context was created.
        /// </summary>
        public DateTimeOffset ContextCreationTime { get; }

        /// <summary>
        /// Gets the file digest algorithm.
        /// </summary>
        public HashAlgorithmName FileDigestAlgorithmName => _configuration.FileDigestAlgorithm;

        /// <summary>
        /// Gets the certificate and public key used to validate the signature.
        /// </summary>
        public X509Certificate2 Certificate => _configuration.PublicCertificate;


        public async Task<byte[]> SignDigestAsync(byte[] digest)
        {
            var client = _configuration.Client;
            var algorithm = SignatureAlgorithmTranslator.SignatureAlgorithmToJwsAlgId(_configuration.FileDigestAlgorithm);
            var signature = await client.SignAsync(_configuration.Key.KeyIdentifier.Identifier, algorithm, digest);
            return signature.Result;
        }

        public Task<bool> VerifyDigestAsync(byte[] digest, byte[] signature)
        {
            using (var publicKey = Certificate.GetRSAPublicKey())
            {
                return Task.FromResult(publicKey.VerifyHash(digest, signature, _configuration.FileDigestAlgorithm, RSASignaturePadding.Pkcs1));
            }
        }

        public void Dispose()
        {
        }
    }
}
