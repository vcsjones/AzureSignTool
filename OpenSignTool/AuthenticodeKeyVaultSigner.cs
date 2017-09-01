using Microsoft.IdentityModel.Clients.ActiveDirectory;
using OpenSignTool.Interop;
using System;
using System.Net.Http;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;

namespace OpenSignTool
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

        public unsafe void SignFile(string path)
        {
            const SignerSignEx3Flags FLAGS = SignerSignEx3Flags.UNDOCUMENTED;
            var zero = stackalloc uint[1];
            *zero = 0;

            var emptyString = Marshal.StringToHGlobalUni("");

            var pathPtr = Marshal.StringToHGlobalUni(path);
            var fileInfo = new SIGNER_FILE_INFO
            {
                cbSize = (uint)Marshal.SizeOf<SIGNER_FILE_INFO>(),
                pwszFileName = pathPtr,
                hFile = IntPtr.Zero
            };

            var storeInfo = new SIGNER_CERT_STORE_INFO
            {
                cbSize = (uint)Marshal.SizeOf<SIGNER_CERT_STORE_INFO>(),
                dwCertPolicy = SignerCertStoreInfoFlags.SIGNER_CERT_POLICY_CHAIN,
                hCertStore = _certificateStore.DangerousGetHandle(),
                pSigningCert = _configuration.PublicCertificate.Handle
            };

            var storeInfoHandle = GCHandle.Alloc(storeInfo, GCHandleType.Pinned);

            var signerCert = new SIGNER_CERT
            {
                cbSize = (uint)Marshal.SizeOf<SIGNER_CERT>(),
                dwCertChoice = SignerCertChoice.SIGNER_CERT_STORE,
                hwnd = IntPtr.Zero,
                union = new SIGNER_CERT_UNION
                {
                    pSpcChainInfo = storeInfoHandle.AddrOfPinnedObject()
                }
            };

            var authCodeAttr = new SIGNER_ATTR_AUTHCODE
            {
                cbSize = (uint)Marshal.SizeOf<SIGNER_ATTR_AUTHCODE>(),
                pwszInfo = emptyString,
                pwszName = emptyString
            };

            var authCodeAttrHandle = GCHandle.Alloc(authCodeAttr, GCHandleType.Pinned);

            var signatureInfo = new SIGNER_SIGNATURE_INFO
            {
                cbSize = (uint)Marshal.SizeOf<SIGNER_SIGNATURE_INFO>(),
                //TODO: don't hardcode SHA256
                algidHash = 0x0000800c,
                psAuthenticated = IntPtr.Zero,
                psUnauthenticated = IntPtr.Zero,
                dwAttrChoice = SignerSignatureInfoAttrChoice.SIGNER_AUTHCODE_ATTR,
                attrAuthUnion = new SIGNER_SIGNATURE_INFO_UNION
                {
                    pAttrAuthcode = authCodeAttrHandle.AddrOfPinnedObject()
                }

            };


            var fileInfoHandle = GCHandle.Alloc(fileInfo, GCHandleType.Pinned);

            var subject = new SIGNER_SUBJECT_INFO
            {
                cbSize = (uint)Marshal.SizeOf<SIGNER_SUBJECT_INFO>(),
                dwSubjectChoice = SignerSubjectInfoUnionChoice.SIGNER_SUBJECT_FILE,
                pdwIndex = zero,
                unionInfo = new SIGNER_SUBJECT_INFO_UNION
                {
                    file = fileInfoHandle.AddrOfPinnedObject(),
                }
            };

            var signInfo = new SIGN_INFO
            {
                cbSize = (uint)Marshal.SizeOf<SIGN_INFO>(),
                pvOpaque = IntPtr.Zero,
                callback = SignCallback
            };

            var signerContext = new SIGNER_CONTEXT();
            var providerInfo = new SIGNER_PROVIDER_INFO();
            providerInfo.pwszProviderName = "";
            providerInfo.union.pwszKeyContainer = "";
            providerInfo.dwPvkChoice = 0x2;
            providerInfo.cbSize = (uint)Marshal.SizeOf<SIGNER_PROVIDER_INFO>();

            var result = mssign32.SignerSignEx3
            (
                FLAGS,
                ref subject,
                ref signerCert,
                ref signatureInfo,
                ref providerInfo,
                IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero,
                ref signerContext,
                IntPtr.Zero,
                ref signInfo,
                IntPtr.Zero
            );

            fileInfoHandle.Free();
            authCodeAttrHandle.Free();
            Marshal.FreeHGlobal(pathPtr);
        }

        public void Dispose()
        {
            _chain.Dispose();
            _certificateStore.Close();
            _configuration.Dispose();
        }

        private int SignCallback(IntPtr pCertContext,
        IntPtr pvExtra,
        uint algId,
        byte[] pDigestToSign,
        uint dwDigestToSign,
        out CRYPTOAPI_BLOB blob)
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
