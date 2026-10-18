#if NET
using Microsoft.Extensions.Logging;
using System;
using System.Formats.Asn1;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace AzureSign.Core
{
    /// <summary>
    /// Signs a NuGet package (.nupkg or .snupkg) with a NuGet author signature.
    /// </summary>
    public class NuGetKeyVaultSigner : IDisposable
    {
        private const int S_OK = 0;
        private const int E_FAIL = unchecked((int)0x80004005);

        private const string SubjectKeyIdentifierOid = "2.5.29.14";
        private const string CommitmentTypeIndicationOid = "1.2.840.113549.1.9.16.2.16";
        private const string CommitmentTypeIdentifierProofOfOriginOid = "1.2.840.113549.1.9.16.6.1";
        private const string SigningCertificateV2Oid = "1.2.840.113549.1.9.16.2.47";
        private const string SignatureTimeStampTokenOid = "1.2.840.113549.1.9.16.2.14";

        private const int TimestampMaxAttempts = 3;

        private static readonly HttpClient s_httpClient = new() { Timeout = TimeSpan.FromSeconds(30) };

        private readonly AsymmetricAlgorithm _signingAlgorithm;
        private readonly X509Certificate2 _signingCertificate;
        private readonly HashAlgorithmName _fileDigestAlgorithm;
        private readonly string _fileDigestOid;
        private readonly TimeStampConfiguration _timeStampConfiguration;
        private readonly X509Chain _chain;

        /// <summary>
        /// Creates a new instance of <see cref="NuGetKeyVaultSigner" />.
        /// </summary>
        /// <param name="signingAlgorithm">
        /// An instance of an RSA algorithm that will be used to sign. It must support signing with a private key.
        /// </param>
        /// <param name="signingCertificate">The X509 public certificate for the <paramref name="signingAlgorithm"/>.</param>
        /// <param name="fileDigestAlgorithm">The digest algorithm used to hash the package and the signature. Must be SHA256, SHA384, or SHA512.</param>
        /// <param name="timeStampConfiguration">The timestamp configuration for timestamping the package. Only RFC 3161 timestamps
        /// are supported. To omit timestamping, use <see cref="TimeStampConfiguration.None"/>.</param>
        /// <param name="additionalCertificates">Any additional certificates to assist in building a certificate chain.</param>
        public NuGetKeyVaultSigner(AsymmetricAlgorithm signingAlgorithm, X509Certificate2 signingCertificate,
            HashAlgorithmName fileDigestAlgorithm, TimeStampConfiguration timeStampConfiguration,
            X509Certificate2Collection? additionalCertificates = null)
        {
            _signingAlgorithm = signingAlgorithm ?? throw new ArgumentNullException(nameof(signingAlgorithm));
            _signingCertificate = signingCertificate ?? throw new ArgumentNullException(nameof(signingCertificate));
            _timeStampConfiguration = timeStampConfiguration ?? throw new ArgumentNullException(nameof(timeStampConfiguration));

            if (signingAlgorithm is not RSA)
            {
                throw new ArgumentException("NuGet package signing requires an RSA key.", nameof(signingAlgorithm));
            }

            if (!IsSupportedDigestAlgorithm(fileDigestAlgorithm))
            {
                throw new ArgumentException("NuGet package signing requires a SHA256, SHA384, or SHA512 file digest.", nameof(fileDigestAlgorithm));
            }

            if (timeStampConfiguration.Type == TimeStampType.Authenticode)
            {
                throw new ArgumentException("NuGet package signing only supports RFC 3161 timestamps.", nameof(timeStampConfiguration));
            }

            if (timeStampConfiguration.Type == TimeStampType.RFC3161 && !IsSupportedDigestAlgorithm(timeStampConfiguration.DigestAlgorithm))
            {
                throw new ArgumentException("NuGet package signing requires a SHA256, SHA384, or SHA512 timestamp digest.", nameof(timeStampConfiguration));
            }

            _fileDigestAlgorithm = fileDigestAlgorithm;
            _fileDigestOid = AlgorithmTranslator.HashAlgorithmToOid(fileDigestAlgorithm);
            _chain = CertificateChainBuilder.Build(signingCertificate, additionalCertificates);
        }

        /// <summary>
        /// Determines if a path refers to a NuGet package, based on its file extension.
        /// </summary>
        /// <param name="path">The path to the file.</param>
        /// <returns><see langword="true"/> if the file has a .nupkg or .snupkg extension, otherwise <see langword="false"/>.</returns>
        public static bool IsNuGetPackage(ReadOnlySpan<char> path)
        {
            ReadOnlySpan<char> extension = Path.GetExtension(path);
            return extension.Equals(".nupkg", StringComparison.OrdinalIgnoreCase) ||
                extension.Equals(".snupkg", StringComparison.OrdinalIgnoreCase);
        }

        /// <summary>
        /// Determines if a NuGet package contains a package signature.
        /// </summary>
        /// <param name="path">The path to the NuGet package.</param>
        /// <returns><see langword="true"/> if the package is signed, otherwise <see langword="false"/>.</returns>
        public static bool IsSigned(string path)
        {
            try
            {
                using FileStream stream = File.OpenRead(path);
                return NuGetPackageArchive.Read(stream).IsSigned;
            }
            catch (Exception e) when (e is InvalidDataException or NotSupportedException or EndOfStreamException or IOException or UnauthorizedAccessException)
            {
                return false;
            }
        }

        /// <summary>Signs a NuGet package with an author signature. Any existing package signature is replaced.</summary>
        /// <param name="path">The path to the package to sign.</param>
        /// <param name="logger">An optional logger to capture signing operations.</param>
        /// <param name="cancellationToken">A token to cancel the timestamp request.</param>
        /// <returns>A HRESULT indicating the result of the signing operation. S_OK, or zero, is returned if the signing
        /// operation completed successfully.</returns>
        public int SignFile(string path, ILogger? logger = null, CancellationToken cancellationToken = default)
        {
            try
            {
                // Open the package for writing up front so a read-only or locked package fails before any signing work is done.
                using FileStream package = new(path, FileMode.Open, FileAccess.ReadWrite, FileShare.None);
                NuGetPackageArchive archive = NuGetPackageArchive.Read(package);
                Stream unsigned = package;

                try
                {
                    if (archive.IsSigned)
                    {
                        logger?.LogTrace("Removing existing package signature.");
                        unsigned = CreateTemporaryFile();
                        archive.WriteWithoutSignature(package, unsigned);
                        unsigned.Position = 0;
                        archive = NuGetPackageArchive.Read(unsigned);
                    }

                    logger?.LogTrace("Hashing package.");
                    unsigned.Position = 0;
                    byte[] packageHash = HashStream(unsigned, _fileDigestAlgorithm);

                    logger?.LogTrace("Creating package signature.");
                    byte[] signature = CreateSignature(packageHash, logger, cancellationToken);

                    using FileStream signed = CreateTemporaryFile();
                    archive.WriteWithSignature(unsigned, signed, signature);

                    // Write the signed package over the original file instead of replacing it, so links,
                    // permissions, and other file metadata are kept.
                    signed.Position = 0;
                    package.Position = 0;
                    signed.CopyTo(package);
                    package.SetLength(signed.Length);
                }
                finally
                {
                    if (!ReferenceEquals(unsigned, package))
                    {
                        unsigned.Dispose();
                    }
                }

                return S_OK;
            }
            catch (Exception e)
            {
                logger?.LogError(e, "Failed to sign NuGet package: {message}", e.Message);
                return e.HResult != 0 ? e.HResult : E_FAIL;
            }
        }

        /// <summary>
        /// Frees all resources used by the <see cref="NuGetKeyVaultSigner" />.
        /// </summary>
        public void Dispose()
        {
            _chain.Dispose();
        }

        private byte[] CreateSignature(byte[] packageHash, ILogger? logger, CancellationToken cancellationToken)
        {
            // The signature content is defined by the NuGet package signing specification, version 1.
            string content = $"Version:1\n\n{_fileDigestOid}-Hash:{Convert.ToBase64String(packageHash)}\n\n";
            byte[] contentBytes = new UTF8Encoding(encoderShouldEmitUTF8Identifier: false).GetBytes(content);

            // Subject Key Identifier is preferred, but should only be used if the certificate has the extension.
            SubjectIdentifierType identifierType = _signingCertificate.Extensions[SubjectKeyIdentifierOid] is null
                ? SubjectIdentifierType.IssuerAndSerialNumber
                : SubjectIdentifierType.SubjectKeyIdentifier;

            CmsSigner signer = new(identifierType, _signingCertificate, _signingAlgorithm)
            {
                DigestAlgorithm = new Oid(_fileDigestOid),
                IncludeOption = X509IncludeOption.None,
            };

            foreach (X509ChainElement element in _chain.ChainElements)
            {
                signer.Certificates.Add(element.Certificate);
            }

            signer.SignedAttributes.Add(new Pkcs9SigningTime());
            signer.SignedAttributes.Add(new AsnEncodedData(CommitmentTypeIndicationOid, EncodeCommitmentTypeIndication()));
            signer.SignedAttributes.Add(new AsnEncodedData(SigningCertificateV2Oid, EncodeSigningCertificateV2(_signingCertificate, _fileDigestAlgorithm, _fileDigestOid)));

            SignedCms cms = new(new ContentInfo(contentBytes), detached: false);
            cms.ComputeSignature(signer, silent: true);

            if (_timeStampConfiguration.Type == TimeStampType.RFC3161)
            {
                logger?.LogTrace("Timestamping package signature.");
                Timestamp(cms.SignerInfos[0], _timeStampConfiguration.Url!, _timeStampConfiguration.DigestAlgorithm, logger, cancellationToken);
            }

            return cms.Encode();
        }

        private static void Timestamp(SignerInfo signerInfo, string timestampUrl, HashAlgorithmName digestAlgorithm, ILogger? logger, CancellationToken cancellationToken)
        {
            byte[] nonce = new byte[8];
            RandomNumberGenerator.Fill(nonce);

            Rfc3161TimestampRequest request = Rfc3161TimestampRequest.CreateFromSignerInfo(
                signerInfo,
                digestAlgorithm,
                requestedPolicyId: null,
                nonce: nonce,
                requestSignerCertificates: true);

            byte[] responseBytes = SendTimestampRequest(request.Encode(), timestampUrl, logger, cancellationToken);

            // ProcessResponse validates the status, the message imprint, and the nonce.
            Rfc3161TimestampToken token = request.ProcessResponse(responseBytes, out _);
            signerInfo.AddUnsignedAttribute(new AsnEncodedData(SignatureTimeStampTokenOid, token.AsSignedCms().Encode()));
        }

        private static byte[] SendTimestampRequest(byte[] request, string timestampUrl, ILogger? logger, CancellationToken cancellationToken)
        {
            for (int attempt = 1; ; attempt++)
            {
                try
                {
                    using HttpRequestMessage message = new(HttpMethod.Post, timestampUrl)
                    {
                        Content = new ByteArrayContent(request),
                    };
                    message.Content.Headers.ContentType = new MediaTypeHeaderValue("application/timestamp-query");

                    using HttpResponseMessage response = s_httpClient.Send(message, cancellationToken);
                    response.EnsureSuccessStatusCode();

                    using Stream responseStream = response.Content.ReadAsStream(cancellationToken);
                    using MemoryStream buffer = new();
                    responseStream.CopyTo(buffer);
                    return buffer.ToArray();
                }
                catch (Exception e) when (attempt < TimestampMaxAttempts && IsTransientTimestampFailure(e, cancellationToken))
                {
                    TimeSpan delay = TimeSpan.FromSeconds(2 * attempt);
                    logger?.LogWarning("Timestamp request failed: {message} Retrying in {delay} seconds.", e.Message, delay.TotalSeconds);

                    if (cancellationToken.WaitHandle.WaitOne(delay))
                    {
                        cancellationToken.ThrowIfCancellationRequested();
                    }
                }
            }
        }

        private static bool IsTransientTimestampFailure(Exception exception, CancellationToken cancellationToken)
        {
            return exception switch
            {
                // HttpClient reports its own timeout as a TaskCanceledException.
                TaskCanceledException => !cancellationToken.IsCancellationRequested,
                HttpRequestException { StatusCode: null } => true,
                HttpRequestException { StatusCode: HttpStatusCode.RequestTimeout or HttpStatusCode.TooManyRequests } => true,
                HttpRequestException { StatusCode: >= HttpStatusCode.InternalServerError } => true,
                _ => false,
            };
        }

        private static byte[] EncodeCommitmentTypeIndication()
        {
            // CommitmentTypeIndication ::= SEQUENCE { commitmentTypeId CommitmentTypeIdentifier, ... }
            AsnWriter writer = new(AsnEncodingRules.DER);

            using (writer.PushSequence())
            {
                writer.WriteObjectIdentifier(CommitmentTypeIdentifierProofOfOriginOid);
            }

            return writer.Encode();
        }

        private static byte[] EncodeSigningCertificateV2(X509Certificate2 certificate, HashAlgorithmName hashAlgorithm, string hashOid)
        {
            // SigningCertificateV2 ::= SEQUENCE { certs SEQUENCE OF ESSCertIDv2 }
            // ESSCertIDv2 ::= SEQUENCE { hashAlgorithm AlgorithmIdentifier, certHash OCTET STRING, issuerSerial IssuerSerial }
            // IssuerSerial ::= SEQUENCE { issuer GeneralNames, serialNumber CertificateSerialNumber }
            byte[] certificateHash = HashData(hashAlgorithm, certificate.RawData);
            AsnWriter writer = new(AsnEncodingRules.DER);

            using (writer.PushSequence())
            using (writer.PushSequence())
            using (writer.PushSequence())
            {
                using (writer.PushSequence())
                {
                    writer.WriteObjectIdentifier(hashOid);
                }

                writer.WriteOctetString(certificateHash);

                using (writer.PushSequence())
                {
                    using (writer.PushSequence())
                    using (writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 4, isConstructed: true)))
                    {
                        // directoryName [4] Name. Name is a CHOICE, so the tag is explicit.
                        writer.WriteEncodedValue(certificate.IssuerName.RawData);
                    }

                    writer.WriteInteger(certificate.SerialNumberBytes.Span);
                }
            }

            return writer.Encode();
        }

        private static byte[] HashStream(Stream stream, HashAlgorithmName hashAlgorithm)
        {
            using IncrementalHash hash = IncrementalHash.CreateHash(hashAlgorithm);
            byte[] buffer = new byte[81920];
            int read;

            while ((read = stream.Read(buffer, 0, buffer.Length)) > 0)
            {
                hash.AppendData(buffer, 0, read);
            }

            return hash.GetHashAndReset();
        }

        private static byte[] HashData(HashAlgorithmName hashAlgorithm, byte[] data)
        {
            using IncrementalHash hash = IncrementalHash.CreateHash(hashAlgorithm);
            hash.AppendData(data);
            return hash.GetHashAndReset();
        }

        private static bool IsSupportedDigestAlgorithm(HashAlgorithmName hashAlgorithm)
        {
            return hashAlgorithm == HashAlgorithmName.SHA256 ||
                hashAlgorithm == HashAlgorithmName.SHA384 ||
                hashAlgorithm == HashAlgorithmName.SHA512;
        }

        private static FileStream CreateTemporaryFile()
        {
            string path = Path.Combine(Path.GetTempPath(), $"AzureSignTool.{Guid.NewGuid():N}.nupkg.tmp");
            return new FileStream(path, FileMode.CreateNew, FileAccess.ReadWrite, FileShare.None, 4096, FileOptions.DeleteOnClose);
        }
    }
}
#endif
