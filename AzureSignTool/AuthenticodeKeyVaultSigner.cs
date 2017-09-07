using AzureSignTool.Interop;
using System;
using System.IO;
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

        public AuthenticodeKeyVaultSigner(AzureKeyVaultMaterializedConfiguration configuration, TimeStampConfiguration timeStampConfiguration)
        {
            _timeStampConfiguration = timeStampConfiguration;
            _configuration = configuration;
            _certificateStore = MemoryCertificateStore.Create();
            _chain = new X509Chain();
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

        public int SignFile(string path, string description, string descriptionUrl)
        {
            var flags = SignerSignEx3Flags.UNDOCUMENTED;

            using (var contextReceiver = new PrimitiveStructureOutManager())
            using (var sipState = new PrimitiveStructureOutManager())
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

                using (var data = SipExtensionFactory.GetSipData(path, flags, contextReceiver, timeStampFlags, storeInfo, timestampUrl, timestampAlgorithmOid, SignCallback, _configuration.FileDigestAlgorithm, fileInfo, attributes))
                {
                    try
                    {
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
                    finally
                    {
                        if (contextReceiver.Object.HasValue)
                        {
                            mssign32.SignerFreeSignerContext(contextReceiver.Object.Value);
                        }
                    }
                }
            }
        }

        public void Dispose()
        {
            _chain.Dispose();
            _certificateStore.Close();
            _configuration.Dispose();
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
            var context = new KeyVaultSigningContext(_configuration);
            var result = context.SignDigestAsync(pDigestToSign).ConfigureAwait(false).GetAwaiter().GetResult();
            var resultPtr = Marshal.AllocHGlobal(result.Length);
            Marshal.Copy(result, 0, resultPtr, result.Length);
            blob.pbData = resultPtr;
            blob.cbData = (uint)result.Length;
            return 0;
        }
    }
}
