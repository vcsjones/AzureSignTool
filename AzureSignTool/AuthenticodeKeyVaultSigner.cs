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
                var signerCert = new SIGNER_CERT
                (
                    dwCertChoice: SignerCertChoice.SIGNER_CERT_STORE,
                    union: new SIGNER_CERT_UNION
                    {
                        pSpcChainInfo = storeInfo.Handle
                    }
                );

                var signatureInfo = new SIGNER_SIGNATURE_INFO(
                    algidHash: AlgorithmTranslator.HashAlgorithmToAlgId(_configuration.FileDigestAlgorithm),
                    psAuthenticated: IntPtr.Zero,
                    psUnauthenticated: IntPtr.Zero,
                    dwAttrChoice: SignerSignatureInfoAttrChoice.SIGNER_AUTHCODE_ATTR,
                    attrAuthUnion: new SIGNER_SIGNATURE_INFO_UNION
                    {
                        pAttrAuthcode = attributes.Handle
                    }
                );

                var subject = new SIGNER_SUBJECT_INFO
                (
                    dwSubjectChoice: SignerSubjectInfoUnionChoice.SIGNER_SUBJECT_FILE,
                    pdwIndex: IntegerCache.Zero,
                    unionInfo: new SIGNER_SUBJECT_INFO_UNION(fileInfo.Handle)
                );

                var callbackPointer = Marshal.GetFunctionPointerForDelegate<SignCallback>(SignCallback);
                var signInfo = new SIGN_INFO(callback: callbackPointer);
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

                var providerInfo = new SIGNER_PROVIDER_INFO
                {
                    cbSize = (uint)Marshal.SizeOf<SIGNER_PROVIDER_INFO>(),
                    dwKeySpec = 0,
                    dwProviderType = 0,
                    dwPvkChoice = 2,
                    pwszProviderName = IntegerCache.EmptyStringW,
                    union = new SIGNER_PROVIDER_INFO_UNION
                    {
                        pwszKeyContainer = IntegerCache.EmptyStringW
                    }
                };

                var providerInfoHandle = GCHandle.Alloc(providerInfo, GCHandleType.Pinned);

                var injectAppxSipData = Path.GetExtension(path)?.ToLowerInvariant() == ".appx";

                if (injectAppxSipData)
                {
                    flags |= SignerSignEx3Flags.SPC_EXC_PE_PAGE_HASHES_FLAG;
                }

                var pSignerCert = GCHandle.Alloc(signerCert, GCHandleType.Pinned);
                var pSubject = GCHandle.Alloc(subject, GCHandleType.Pinned);
                var pSignatureInfo = GCHandle.Alloc(signatureInfo, GCHandleType.Pinned);
                var signInfoHandle = GCHandle.Alloc(signInfo, GCHandleType.Pinned);

                var paramsStructure = new SIGNER_SIGN_EX2_PARAMS
                {
                    dwFlags = flags,
                    dwTimestampFlags = timeStampFlags,
                    pCryptoPolicy = IntPtr.Zero,
                    pProviderInfo = providerInfoHandle.AddrOfPinnedObject(),
                    ppSignerContext = IntPtr.Zero,
                    pReserved = IntPtr.Zero,
                    psRequest = IntPtr.Zero,
                    pwszHttpTimeStamp = Marshal.StringToHGlobalUni(timestampUrl),
                    pszTimestampAlgorithmOid = Marshal.StringToHGlobalAnsi(timestampAlgorithmOid),
                    pSignerCert = pSignerCert.AddrOfPinnedObject(),
                    pSubjectInfo = pSubject.AddrOfPinnedObject(),
                    pSignatureInfo = pSignatureInfo.AddrOfPinnedObject(),
                    pSipData = signInfoHandle.AddrOfPinnedObject()
                };

                var paramsHandle = GCHandle.Alloc(paramsStructure, GCHandleType.Pinned);
                var clientData = new APPX_SIP_CLIENT_DATA();
                clientData.pSignerParams = paramsHandle.AddrOfPinnedObject();
                clientData.pAppxSipState = IntPtr.Zero;

                var clientDataHandle = GCHandle.Alloc(clientData, GCHandleType.Pinned);
                var sipData = injectAppxSipData ? clientDataHandle.AddrOfPinnedObject() : IntPtr.Zero;


                try
                {
                    return mssign32.SignerSignEx3
                    (
                        paramsStructure.dwFlags,
                        paramsStructure.pSubjectInfo,
                        paramsStructure.pSignerCert,
                        paramsStructure.pSignatureInfo,
                        paramsStructure.pProviderInfo,
                        paramsStructure.dwTimestampFlags,
                        paramsStructure.pszTimestampAlgorithmOid,
                        paramsStructure.pwszHttpTimeStamp,
                        paramsStructure.psRequest,
                        sipData,
                        contextReceiver.Handle,
                        paramsStructure.pCryptoPolicy,
                        ref signInfo,
                        paramsStructure.pReserved
                    );
                }
                finally
                {
                    if (contextReceiver.Object.HasValue)
                    {
                        mssign32.SignerFreeSignerContext(contextReceiver.Object.Value);
                    }
                    if (sipState.Object.HasValue)
                    {
                        Marshal.Release(sipState.Object.Value);
                    }
                    pSignerCert.Free();
                    pSubject.Free();
                    pSignatureInfo.Free();
                    paramsHandle.Free();
                    clientDataHandle.Free();
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
