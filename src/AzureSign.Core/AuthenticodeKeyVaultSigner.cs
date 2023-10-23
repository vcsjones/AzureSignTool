using static Windows.Win32.PInvoke;
using Windows.Win32.Security.Cryptography;
using AzureSign.Core.Interop;
using Microsoft.Extensions.Logging;
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Windows.Win32.Foundation;

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
        /// <returns>A HRESULT indicating the result of the signing operation. S_OK, or zero, is returned if the signing
        /// operation completed successfully.</returns>
        public unsafe int SignFile(ReadOnlySpan<char> path, ReadOnlySpan<char> description, ReadOnlySpan<char> descriptionUrl, bool? pageHashing, ILogger? logger = null)
        {
            static char[] NullTerminate(ReadOnlySpan<char> str)
            {
                char[] result = new char[str.Length + 1];
                str.CopyTo(result);
                result[result.Length - 1] = '\0';
                return result;
            }

            SIGNER_SIGN_FLAGS flags = SIGNER_SIGN_FLAGS.SPC_DIGEST_SIGN_FLAG;

            if (pageHashing == true)
            {
                flags |= SIGNER_SIGN_FLAGS.SPC_INC_PE_PAGE_HASHES_FLAG;
            }
            else if (pageHashing == false)
            {
                flags |= SIGNER_SIGN_FLAGS.SPC_EXC_PE_PAGE_HASHES_FLAG;
            }

            SIGNER_TIMESTAMP_FLAGS timeStampFlags;
            string? timestampAlgorithmOid = null;
            string? timestampUrl;

            switch (_timeStampConfiguration.Type)
            {
                case TimeStampType.Authenticode:
                    timeStampFlags = SIGNER_TIMESTAMP_FLAGS.SIGNER_TIMESTAMP_AUTHENTICODE;
                    timestampUrl = _timeStampConfiguration.Url;
                    break;
                case TimeStampType.RFC3161:
                    timeStampFlags = SIGNER_TIMESTAMP_FLAGS.SIGNER_TIMESTAMP_RFC3161;
                    timestampAlgorithmOid = AlgorithmTranslator.HashAlgorithmToOidAsciiTerminated(_timeStampConfiguration.DigestAlgorithm);
                    timestampUrl = _timeStampConfiguration.Url;
                    break;
                default:
                    timeStampFlags = default;
                    timestampUrl = null;
                    break;
            }

            fixed (char* pTimestampUrl = timestampUrl)
            fixed (char* pPath = NullTerminate(path))
            fixed (char* pDescription = NullTerminate(description))
            fixed (char* pDescriptionUrl = NullTerminate(descriptionUrl))
            {
                var fileInfo = new SIGNER_FILE_INFO()
                {
                    cbSize = (uint)Marshal.SizeOf<SIGNER_FILE_INFO>(),
                    hFile = default,
                    pwszFileName = pPath,
                };
                var subjectIndex = 0u;
                var subjectInfo = new SIGNER_SUBJECT_INFO
                {
                    cbSize = (uint)Marshal.SizeOf<SIGNER_SUBJECT_INFO>(),
                    pdwIndex = &subjectIndex,
                    dwSubjectChoice = SIGNER_SUBJECT_CHOICE.SIGNER_SUBJECT_FILE,
                    Anonymous = new() { pSignerFileInfo = &fileInfo }
                };
                var authCodeStructure = new SIGNER_ATTR_AUTHCODE
                {
                    cbSize = (uint)Marshal.SizeOf<SIGNER_ATTR_AUTHCODE>(),
                    fCommercial = false,
                    fIndividual = false,
                    pwszName = pDescription,
                    pwszInfo = pDescriptionUrl,

                };

                var storeInfo = new SIGNER_CERT_STORE_INFO
                {
                    cbSize = (uint)Marshal.SizeOf<SIGNER_CERT_STORE_INFO>(),
                    dwCertPolicy = SIGNER_CERT_POLICY.SIGNER_CERT_POLICY_CHAIN,
                    hCertStore = _certificateStore.Handle,
                    pSigningCert = (CERT_CONTEXT*)_signingCertificate.Handle
                };

                var signerCert = new SIGNER_CERT()
                {
                    cbSize = (uint)Marshal.SizeOf<SIGNER_CERT>(),
                    dwCertChoice = SIGNER_CERT_CHOICE.SIGNER_CERT_STORE,
                    Anonymous = new() { pCertStoreInfo = &storeInfo },
                };

                var signatureInfo = new SIGNER_SIGNATURE_INFO
                {
                    cbSize = (uint)Marshal.SizeOf<SIGNER_SIGNATURE_INFO>(),
                    algidHash = AlgorithmTranslator.HashAlgorithmToAlgId(_fileDigestAlgorithm),
                    psAuthenticated = null,
                    psUnauthenticated = null,
                    dwAttrChoice = SIGNER_SIGNATURE_ATTRIBUTE_CHOICE.SIGNER_AUTHCODE_ATTR,
                    Anonymous = new() { pAttrAuthcode = &authCodeStructure }
                };

                var callbackPtr = Marshal.GetFunctionPointerForDelegate(_signCallback);
                var signCallbackInfo = new SIGNER_DIGEST_SIGN_INFO
                {
                    cbSize = 24,
                    Anonymous = new()
                    {
                        pfnAuthenticodeDigestSign =
                            (delegate* unmanaged[Stdcall]<
                            CERT_CONTEXT*,
                            CRYPT_INTEGER_BLOB*,
                            uint,
                            byte*,
                            uint,
                            CRYPT_INTEGER_BLOB*, HRESULT>)
                        callbackPtr
                    },
                };

                logger?.LogTrace("Getting SIP Data");
                var sipKind = SipExtensionFactory.GetSipKind(path);
                void* sipData = (void*)0;
                SIGNER_CONTEXT* pContext = null;

                switch (sipKind)
                {
                    case SipKind.Appx:
                        APPX_SIP_CLIENT_DATA clientData;
                        SIGNER_SIGN_EX3_PARAMS parameters;
                        clientData.pSignerParams = &parameters;
                        sipData = &clientData;
                        flags &= ~SIGNER_SIGN_FLAGS.SPC_INC_PE_PAGE_HASHES_FLAG;
                        flags |= SIGNER_SIGN_FLAGS.SPC_EXC_PE_PAGE_HASHES_FLAG;
                        FillAppxExtension(ref clientData, flags, timeStampFlags, &subjectInfo, &signerCert, &signatureInfo, pContext, pTimestampUrl, timestampAlgorithmOid, &signCallbackInfo);
                        break;
                }

                logger?.LogTrace("Calling SignerSignEx3");
                var result = SignerSignEx3
                (
                    flags,
                    subjectInfo,
                    signerCert,
                    signatureInfo,
                    null,
                    timeStampFlags,
                    timestampAlgorithmOid,
                    timestampUrl,
                    null,
                    sipData,
                    out pContext,
                    null,
                    signCallbackInfo
                );
                if (result == HRESULT.S_OK && pContext != null)
                {
                    Debug.Assert(SignerFreeSignerContext(pContext) == HRESULT.S_OK);
                }
                if (result == HRESULT.S_OK && sipKind == SipKind.Appx)
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
            ref CRYPT_INTEGER_BLOB blob
        )
        {
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
                    return HRESULT.E_INVALIDARG;
            }
            var resultPtr = Marshal.AllocHGlobal(digest.Length);
            Marshal.Copy(digest, 0, resultPtr, digest.Length);
            blob.pbData = (byte*)resultPtr;
            blob.cbData = (uint)digest.Length;
            return HRESULT.S_OK;
        }

        private static unsafe void FillAppxExtension(
            ref APPX_SIP_CLIENT_DATA clientData,
            SIGNER_SIGN_FLAGS flags,
            SIGNER_TIMESTAMP_FLAGS timestampFlags,
            SIGNER_SUBJECT_INFO* signerSubjectInfo,
            SIGNER_CERT* signerCert,
            SIGNER_SIGNATURE_INFO* signatureInfo,
            SIGNER_CONTEXT* signerContext,
            char* timestampUrl,
            string? timestampOid,
            SIGNER_DIGEST_SIGN_INFO* signInfo
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
