using System.Security.Cryptography;

namespace AzureSignTool
{
    public class TimeStampConfiguration
    {
        public string Url { get; set; }
        public HashAlgorithmName DigestAlgorithm { get; set; }
        public TimeStampType Type { get; set; }
    }

    public enum TimeStampType
    {
        None,
        Authenticode,
        RFC3161
    }
}
