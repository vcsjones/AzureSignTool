using AzureSign.Core.Interop;
using Microsoft.Extensions.Logging;
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace AzureSign.Core
{
    /// <summary>
    /// Signs a file with an Authenticode signature.
    /// </summary>
    public class AuthenticodeKeyVaultSigner : IDisposable
    {
        private readonly AsymmetricAlgorithm _signingAlgorithm;
        private readonly X509Certificate2 _signingCertificate;
        private readonly HashAlgorithmName _fileDigestAlgorithm;
        private readonly TimeStampConfiguration _timeStampConfiguration;
        private readonly MemoryCertificateStore _certificateStore;
        private readonly X509Chain _chain;
        private readonly SignCallback _signCallback;


        /// <summary>
        /// Creates a new instance of <see cref="AuthenticodeKeyVaultSigner" />.
        /// </summary>
        /// <param name="signingAlgorithm">
        /// An instance of an asymmetric algorithm that will be used to sign. It must support signing with
        /// a private key.
        /// </param>
        /// <param name="signingCertificate">The X509 public certificate for the <paramref name="signingAlgorithm"/>.</param>
        /// <param name="fileDigestAlgorithm">The digest algorithm to sign the file.</param>
        /// <param name="timeStampConfiguration">The timestamp configuration for timestamping the file. To omit timestamping,
        /// use <see cref="TimeStampConfiguration.None"/>.</param>
        /// <param name="additionalCertificates">Any additional certificates to assist in building a certificate chain.</param>
        public AuthenticodeKeyVaultSigner(AsymmetricAlgorithm signingAlgorithm, X509Certificate2 signingCertificate,
            HashAlgorithmName fileDigestAlgorithm, TimeStampConfiguration timeStampConfiguration,
            X509Certificate2Collection? additionalCertificates = null)
        {
            _fileDigestAlgorithm = fileDigestAlgorithm;
            _signingCertificate = signingCertificate ?? throw new ArgumentNullException(nameof(signingCertificate));
            _timeStampConfiguration = timeStampConfiguration ?? throw new ArgumentNullException(nameof(timeStampConfiguration));
            _signingAlgorithm = signingAlgorithm ?? throw new ArgumentNullException(nameof(signingAlgorithm));
            _certificateStore = MemoryCertificateStore.Create();
            _chain = new X509Chain();

            if (additionalCertificates is not null)
            {
                _chain.ChainPolicy.ExtraStore.AddRange(additionalCertificates);
            }

            //We don't care about the trustworthiness of the cert. We just want a chain to sign with.
            _chain.ChainPolicy.VerificationFlags = X509VerificationFlags.AllFlags;


            if (!_chain.Build(signingCertificate))
            {
                throw new InvalidOperationException("Failed to build chain for certificate.");
            }
            for (var i = 0; i < _chain.ChainElements.Count; i++)
            {
                _certificateStore.Add(_chain.ChainElements[i].Certificate);
            }
            _signCallback = SignCallback;
        }

        /// <summary>Authenticode signs a file.</summary>
        /// <param name="pageHashing">True if the signing process should try to include page hashing, otherwise false.
        /// Use <c>null</c> to use the operating system default. Note that page hashing still may be disabled if the
        /// Subject Interface Package does not support page hashing.</param>
        /// <param name="descriptionUrl">A URL describing the signature or the signer.</param>
        /// <param name="description">The description to apply to the signature.</param>
        /// <param name="path">The path to the file to signed.</param>
        /// <param name="logger">An optional logger to capture signing operations.</param>
        /// <param name="appendSignature"><see langword="true"/> if the signature should be appended to an existing signature. When <see langword="false"/>, any existing signatures will be replaced.</param>
        /// <returns>A HRESULT indicating the result of the signing operation. S_OK, or zero, is returned if the signing
        /// operation completed successfully.</returns>
        /// <exception cref="PlatformNotSupportedException"><paramref name="appendSignature"/> was set to <see langword="true"/> however the current operating system does not support appending signatures.</exception>
        public unsafe int SignFile(ReadOnlySpan<char> path, ReadOnlySpan<char> description, ReadOnlySpan<char> descriptionUrl, bool? pageHashing, ILogger? logger = null, bool appendSignature = false)
        {
            static char[] NullTerminate(ReadOnlySpan<char> str)
            {
                char[] result = new char[str.Length + 1];
                str.CopyTo(result);
                result[result.Length - 1] = '\0';
                return result;
            }

            SignerSignEx3Flags flags = SignerSignEx3Flags.SIGN_CALLBACK_UNDOCUMENTED;

            if (pageHashing == true)
            {
                flags |= SignerSignEx3Flags.SPC_INC_PE_PAGE_HASHES_FLAG;
            }
            else if (pageHashing == false)
            {
                flags |= SignerSignEx3Flags.SPC_EXC_PE_PAGE_HASHES_FLAG;
            }

            if (appendSignature)
            {
                if (_timeStampConfiguration.Type == TimeStampType.Authenticode)
                {
                    // E_INVALIDARG is expected from SignerSignEx3, no need to override this error, log warning for troubleshooting
                    logger?.LogWarning("If you set the dwTimestampFlags parameter to SIGNER_TIMESTAMP_AUTHENTICODE, you cannot set the dwFlags parameter to SIG_APPEND.");
                }

                flags |= SignerSignEx3Flags.SIG_APPEND;
            }

            SignerSignTimeStampFlags timeStampFlags;
            ReadOnlySpan<byte> timestampAlgorithmOid;
            string? timestampUrl;

            switch (_timeStampConfiguration.Type)
            {
                case TimeStampType.Authenticode:
                    timeStampFlags = SignerSignTimeStampFlags.SIGNER_TIMESTAMP_AUTHENTICODE;
                    timestampAlgorithmOid = default;
                    timestampUrl = _timeStampConfiguration.Url;
                    break;
                case TimeStampType.RFC3161:
                    timeStampFlags = SignerSignTimeStampFlags.SIGNER_TIMESTAMP_RFC3161;
                    timestampAlgorithmOid = AlgorithmTranslator.HashAlgorithmToOidAsciiTerminated(_timeStampConfiguration.DigestAlgorithm);
                    timestampUrl = _timeStampConfiguration.Url;
                    break;
                default:
                    timeStampFlags = default;
                    timestampAlgorithmOid = default;
                    timestampUrl = null;
                    break;
            }

            fixed (byte* pTimestampAlgorithm = timestampAlgorithmOid)
            fixed (char* pTimestampUrl = timestampUrl)
            fixed (char* pPath = NullTerminate(path))
            fixed (char* pDescription = NullTerminate(description))
            fixed (char* pDescriptionUrl = NullTerminate(descriptionUrl))
            {
                var fileInfo = new SIGNER_FILE_INFO(pPath, default);
                var subjectIndex = 0u;
                var signerSubjectInfoUnion = new SIGNER_SUBJECT_INFO_UNION(&fileInfo);
                var subjectInfo = new SIGNER_SUBJECT_INFO(&subjectIndex, SignerSubjectInfoUnionChoice.SIGNER_SUBJECT_FILE, signerSubjectInfoUnion);
                var authCodeStructure = new SIGNER_ATTR_AUTHCODE(pDescription, pDescriptionUrl);
                var storeInfo = new SIGNER_CERT_STORE_INFO(
                    dwCertPolicy: SignerCertStoreInfoFlags.SIGNER_CERT_POLICY_CHAIN,
                    hCertStore: _certificateStore.Handle,
                    pSigningCert: _signingCertificate.Handle
                );
                var signerCert = new SIGNER_CERT(
                    dwCertChoice: SignerCertChoice.SIGNER_CERT_STORE,
                    union: new SIGNER_CERT_UNION(&storeInfo)
                );
                var signatureInfo = new SIGNER_SIGNATURE_INFO(
                    algidHash: AlgorithmTranslator.HashAlgorithmToAlgId(_fileDigestAlgorithm),
                    psAuthenticated: IntPtr.Zero,
                    psUnauthenticated: IntPtr.Zero,
                    dwAttrChoice: SignerSignatureInfoAttrChoice.SIGNER_AUTHCODE_ATTR,
                    attrAuthUnion: new SIGNER_SIGNATURE_INFO_UNION(&authCodeStructure)
                );
                var callbackPtr = Marshal.GetFunctionPointerForDelegate(_signCallback);
                var signCallbackInfo = new SIGN_INFO(callbackPtr);

                logger?.LogTrace("Getting SIP Data");
                var sipKind = SipExtensionFactory.GetSipKind(path);
                void* sipData = (void*)0;
                IntPtr context = IntPtr.Zero;

                switch (sipKind)
                {
                    case SipKind.Appx:
                        APPX_SIP_CLIENT_DATA clientData;
                        SIGNER_SIGN_EX3_PARAMS parameters;
                        clientData.pSignerParams = &parameters;
                        sipData = &clientData;
                        flags &= ~SignerSignEx3Flags.SPC_INC_PE_PAGE_HASHES_FLAG;
                        flags |= SignerSignEx3Flags.SPC_EXC_PE_PAGE_HASHES_FLAG;
                        FillAppxExtension(ref clientData, flags, timeStampFlags, &subjectInfo, &signerCert, &signatureInfo, &context, pTimestampUrl, pTimestampAlgorithm, &signCallbackInfo);
                        break;
                }

                logger?.LogTrace($"Calling SignerSignEx3 with flags: {flags}");
                var result = mssign32.SignerSignEx3
                (
                    flags,
                    &subjectInfo,
                    &signerCert,
                    &signatureInfo,
                    IntPtr.Zero,
                    timeStampFlags,
                    pTimestampAlgorithm,
                    pTimestampUrl,
                    IntPtr.Zero,
                    sipData,
                    &context,
                    IntPtr.Zero,
                    &signCallbackInfo,
                    IntPtr.Zero
                );
                if (result == 0 && context != IntPtr.Zero)
                {
                    Debug.Assert(mssign32.SignerFreeSignerContext(context) == 0);
                }
                if (result == 0 && sipKind == SipKind.Appx)
                {
                    var state = ((APPX_SIP_CLIENT_DATA*)sipData)->pAppxSipState;
                    if (state != IntPtr.Zero)
                    {
                        Marshal.Release(state);
                    }
                }
                return result;
            }
        }

        /// <summary>
        /// Frees all resources used by the <see cref="AuthenticodeKeyVaultSigner" />.
        /// </summary>
        public void Dispose()
        {
            _chain.Dispose();
            _certificateStore.Close();
        }

        private unsafe int SignCallback(
            IntPtr pCertContext,
            IntPtr pvExtra,
            uint algId,
            byte[] pDigestToSign,
            uint dwDigestToSign,
            ref CRYPTOAPI_BLOB blob
        )
        {
            const int E_INVALIDARG = unchecked((int)0x80070057);
            byte[] digest;
            switch (_signingAlgorithm)
            {
                case RSA rsa:
                    digest = rsa.SignHash(pDigestToSign, _fileDigestAlgorithm, RSASignaturePadding.Pkcs1);
                    break;
                case ECDsa ecdsa:
                    digest = ecdsa.SignHash(pDigestToSign);
                    break;
                default:
                    return E_INVALIDARG;
            }
            var resultPtr = Marshal.AllocHGlobal(digest.Length);
            Marshal.Copy(digest, 0, resultPtr, digest.Length);
            blob.pbData = resultPtr;
            blob.cbData = (uint)digest.Length;
            return 0;
        }

        private static unsafe void FillAppxExtension(
            ref APPX_SIP_CLIENT_DATA clientData,
            SignerSignEx3Flags flags,
            SignerSignTimeStampFlags timestampFlags,
            SIGNER_SUBJECT_INFO* signerSubjectInfo,
            SIGNER_CERT* signerCert,
            SIGNER_SIGNATURE_INFO* signatureInfo,
            IntPtr* signerContext,
            char* timestampUrl,
            byte* timestampOid,
            SIGN_INFO* signInfo
        )
        {
            clientData.pSignerParams->dwFlags = flags;
            clientData.pSignerParams->dwTimestampFlags = timestampFlags;
            clientData.pSignerParams->pSubjectInfo = signerSubjectInfo;
            clientData.pSignerParams->pSignerCert = signerCert;
            clientData.pSignerParams->pSignatureInfo = signatureInfo;
            clientData.pSignerParams->ppSignerContext = signerContext;
            clientData.pSignerParams->pwszHttpTimeStamp = timestampUrl;
            clientData.pSignerParams->pszTimestampAlgorithmOid = timestampOid;
            clientData.pSignerParams->pSignCallBack = signInfo;

        }
    }
}
