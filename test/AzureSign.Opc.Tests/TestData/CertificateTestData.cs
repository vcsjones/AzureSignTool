using System.Security.Cryptography;

namespace AzureSign.Opc.Tests.TestData;

public class CertificateTestData : TheoryData<HashAlgorithmName, int>
{
    public CertificateTestData()
    {
        Add(HashAlgorithmName.SHA256, 2048);
        Add(HashAlgorithmName.SHA384, 2048);
        Add(HashAlgorithmName.SHA384, 3072);
        Add(HashAlgorithmName.SHA384, 4096);
        Add(HashAlgorithmName.SHA512, 2048);
    }
}
