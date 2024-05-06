#nullable enable
using Azure.Identity;
using System;
using System.Collections.Generic;
using System.Collections.Immutable;

namespace AzureSignTool
{
    internal static class AuthorityHostNames
    {
        private static readonly ImmutableDictionary<string, Uri> _map = ImmutableDictionary.CreateRange(
            StringComparer.OrdinalIgnoreCase,
            [
                KeyValuePair.Create("gov", AzureAuthorityHosts.AzureGovernment),
                KeyValuePair.Create("germany", AzureAuthorityHosts.AzureGermany),
                KeyValuePair.Create("china", AzureAuthorityHosts.AzureChina),
                KeyValuePair.Create("public", AzureAuthorityHosts.AzurePublicCloud),
            ]);

        public static IEnumerable<string> Keys => _map.Keys;

        public static Uri? GetUriForAzureAuthorityIdentifier(string identifier)
        {
            if (_map.TryGetValue(identifier, out Uri? host))
            {
                return host;
            }

            return null;
        }
    }
}
