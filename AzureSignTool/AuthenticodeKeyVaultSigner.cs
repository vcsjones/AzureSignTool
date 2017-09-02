using AzureSignTool.Interop;
using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;

namespace AzureSignTool
{
    public class AuthenticodeKeyVaultSigner : IDisposable
    {
        private readonly AzureKeyVaultMaterializedConfiguration _configuration;
        private readonly MemoryCertificateStore _certificateStore;
        private readonly X509Chain _chain;

        public AuthenticodeKeyVaultSigner(AzureKeyVaultMaterializedConfiguration configuration)
        {
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
            const SignerSignEx3Flags FLAGS = SignerSignEx3Flags.UNDOCUMENTED;

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

                var signInfo = new SIGN_INFO(callback: SignCallback);
                SignerContextSafeHandle signerContext = null;
                int result = unchecked((int)0xFFFFFFFF);
                try
                {
                    result = mssign32.SignerSignEx3
                    (
                        FLAGS,
                        ref subject,
                        ref signerCert,
                        ref signatureInfo,
                        IntPtr.Zero,
                        IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero,
                        out signerContext,
                        IntPtr.Zero,
                        ref signInfo,
                        IntPtr.Zero
                    );
                    return result; 
                }
                finally
                {
                    if (result == 0 && !signerContext?.IsInvalid == false)
                    {
                        signerContext.Close();
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
