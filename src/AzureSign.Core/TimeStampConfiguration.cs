using System.Security.Cryptography;

namespace AzureSign.Core
{
    public class TimeStampConfiguration
    {
        public string Url { get; }
        public HashAlgorithmName DigestAlgorithm { get; }
        public TimeStampType? Type { get; }

        public static TimeStampConfiguration None { get; } = new TimeStampConfiguration();

        public TimeStampConfiguration(string url, HashAlgorithmName digestAlgorithm, TimeStampType type)
        {
            Url = url;
            DigestAlgorithm = digestAlgorithm;
            Type = type;
        }

        private TimeStampConfiguration()
        {
            Type = null;
        }
    }


    public enum TimeStampType
    {
        Authenticode,
        RFC3161
    }
}
