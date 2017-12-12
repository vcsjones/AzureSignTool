using Microsoft.Azure.KeyVault;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;

namespace AzureSignTool
{

    /// <summary>
    /// A signing context used for signing packages with Azure Key Vault Keys.
    /// </summary>
    public class KeyVaultSigningContext
    {
        private readonly AzureKeyVaultMaterializedConfiguration _configuration;
        private readonly ILogger _logger;

        /// <summary>
        /// Creates a new siging context.
        /// </summary>
        public KeyVaultSigningContext(AzureKeyVaultMaterializedConfiguration configuration, ILogger logger)
        {
            _configuration = configuration;
            _logger = logger;
        }

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
            _logger.Log("Signing digest with key.", LogLevel.Verbose);
            var client = _configuration.Client;
            var algorithm = AlgorithmTranslator.SignatureAlgorithmToRsaJwsAlgId(_configuration.FileDigestAlgorithm);
            var signature = await client.SignAsync(_configuration.Key.KeyIdentifier.Identifier, algorithm, digest).ConfigureAwait(false);
            _logger.Log("Signed digest with key.", LogLevel.Verbose);
            return signature.Result;
        }

        public Task<bool> VerifyDigestAsync(byte[] digest, byte[] signature)
        {
            using (var publicKey = Certificate.GetRSAPublicKey())
            {
                return Task.FromResult(publicKey.VerifyHash(digest, signature, _configuration.FileDigestAlgorithm, RSASignaturePadding.Pkcs1));
            }
        }
    }
}
