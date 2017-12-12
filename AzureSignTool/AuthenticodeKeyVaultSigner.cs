using AzureSignTool.Interop;
using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;

namespace AzureSignTool
{
    public class AuthenticodeKeyVaultSigner : IDisposable
    {
        private readonly AzureKeyVaultMaterializedConfiguration _configuration;
        private readonly TimeStampConfiguration _timeStampConfiguration;
        private readonly MemoryCertificateStore _certificateStore;
        private readonly X509Chain _chain;
        private readonly ILogger _logger;

        public AuthenticodeKeyVaultSigner(AzureKeyVaultMaterializedConfiguration configuration, TimeStampConfiguration timeStampConfiguration, X509Certificate2Collection additionalCertificates,
            ILogger logger)
        {
            _logger = logger;
            _timeStampConfiguration = timeStampConfiguration;
            _configuration = configuration;
            _certificateStore = MemoryCertificateStore.Create();
            _chain = new X509Chain();
            _chain.ChainPolicy.ExtraStore.AddRange(additionalCertificates);
            //We don't care about the trustworthiness of the cert. We just want a chain to sign with.
            _chain.ChainPolicy.VerificationFlags = X509VerificationFlags.AllFlags;


            if (!_chain.Build(_configuration.PublicCertificate))
            {
                throw new InvalidOperationException("Failed to build chain for certificate.");
            }
            for (var i = 0; i < _chain.ChainElements.Count; i++)
            {
                _certificateStore.Add(_chain.ChainElements[i].Certificate);
            }
        }

        public int SignFile(string path, string description, string descriptionUrl, bool? pageHashing)
        {
            var flags = SignerSignEx3Flags.SIGN_CALLBACK_UNDOCUMENTED;
            if (pageHashing == true)
            {
                flags |= SignerSignEx3Flags.SPC_INC_PE_PAGE_HASHES_FLAG;
            }
            else if (pageHashing == false)
            {
                flags |= SignerSignEx3Flags.SPC_EXC_PE_PAGE_HASHES_FLAG;
            }

            using (var contextReceiver = PrimitiveStructureOutManager.Create(mssign32.SignerFreeSignerContext))
            using (var sipState = PrimitiveStructureOutManager.Create())
            using (var storeInfo = new AuthenticodeSignerCertStoreInfo(_certificateStore, _configuration.PublicCertificate))
            using (var fileInfo = new AuthenticodeSignerFile(path))
            using (var attributes = new AuthenticodeSignerAttributes(description, descriptionUrl))
            {
                SignerSignTimeStampFlags timeStampFlags;
                string timestampAlgorithmOid;
                string timestampUrl;
                switch (_timeStampConfiguration.Type)
                {
                    case TimeStampType.Authenticode:
                        timeStampFlags = SignerSignTimeStampFlags.SIGNER_TIMESTAMP_AUTHENTICODE;
                        timestampAlgorithmOid = null;
                        timestampUrl = _timeStampConfiguration.Url;
                        break;
                    case TimeStampType.RFC3161:
                        timeStampFlags = SignerSignTimeStampFlags.SIGNER_TIMESTAMP_RFC3161;
                        timestampAlgorithmOid = AlgorithmTranslator.HashAlgorithmToOid(_timeStampConfiguration.DigestAlgorithm);
                        timestampUrl = _timeStampConfiguration.Url;
                        break;
                    default:
                        timeStampFlags = 0;
                        timestampAlgorithmOid = null;
                        timestampUrl = null;
                        break;
                }

                _logger.Log("Getting SIP Data", LogLevel.Verbose);
                using (var data = SipExtensionFactory.GetSipData(path, flags, contextReceiver, timeStampFlags, storeInfo, timestampUrl,
                    timestampAlgorithmOid, SignCallback, _configuration.FileDigestAlgorithm, fileInfo, attributes))
                {
                    _logger.Log("Calling SignerSignEx3", LogLevel.Verbose);
                    return mssign32.SignerSignEx3
                    (
                        data.ModifyFlags(flags),
                        data.SubjectInfoHandle,
                        data.SignerCertHandle,
                        data.SignatureInfoHandle,
                        IntPtr.Zero,
                        timeStampFlags,
                        data.TimestampAlgorithmOidHandle,
                        data.TimestampUrlHandle,
                        IntPtr.Zero,
                        data.SipDataHandle,
                        contextReceiver.Handle,
                        IntPtr.Zero,
                        data.SignInfoHandle,
                        IntPtr.Zero
                    );
                }
            }
        }

        public void Dispose()
        {
            _chain.Dispose();
            _certificateStore.Close();
        }

        private int SignCallback(
            IntPtr pCertContext,
            IntPtr pvExtra,
            uint algId,
            byte[] pDigestToSign,
            uint dwDigestToSign,
            out CRYPTOAPI_BLOB blob
        )
        {
            _logger.Log("SignCallback", LogLevel.Verbose);
            var context = new KeyVaultSigningContext(_configuration, _logger);
            var result = context.SignDigestAsync(pDigestToSign).ConfigureAwait(false).GetAwaiter().GetResult();
            var resultPtr = Marshal.AllocHGlobal(result.Length);
            Marshal.Copy(result, 0, resultPtr, result.Length);
            blob.pbData = resultPtr;
            blob.cbData = (uint)result.Length;
            return 0;
        }
    }
}
