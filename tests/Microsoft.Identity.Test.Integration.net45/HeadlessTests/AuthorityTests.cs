﻿// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Threading.Tasks;
using Microsoft.Identity.Client;
using Microsoft.Identity.Client.Instance.Discovery;
using Microsoft.Identity.Client.Utils;
using Microsoft.Identity.Test.Common.Core.Helpers;
using Microsoft.Identity.Test.LabInfrastructure;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Microsoft.Identity.Test.Integration.HeadlessTests
{
    [TestClass]
    public class AuthorityMigrationTests
    {
        private static readonly string[] s_scopes = { "User.Read" };

        [TestMethod]
        public async Task AuthorityMigrationAsync()
        {
            LabResponse labResponse = await LabUserHelper.GetDefaultUserAsync().ConfigureAwait(false);
            LabUser user = labResponse.User;

            IPublicClientApplication pca = PublicClientApplicationBuilder
                .Create(labResponse.AppId)
                .Build();

            Trace.WriteLine("Acquire a token using a not so common authority alias");

            AuthenticationResult authResult = await pca.AcquireTokenByUsernamePassword(
               s_scopes,
                user.Upn,
                new NetworkCredential("", user.GetOrFetchPassword()).SecurePassword)
                .WithAuthority("https://sts.windows.net/" + user.CurrentTenantId + "/")
                .ExecuteAsync()
                .ConfigureAwait(false);

            Assert.IsNotNull(authResult.AccessToken);

            Trace.WriteLine("Acquire a token silently using the common authority alias");

            authResult = await pca.AcquireTokenSilent(s_scopes, (await pca.GetAccountsAsync().ConfigureAwait(false)).First())
                .WithAuthority(AadAuthorityAudience.AzureAdMultipleOrgs)
                .ExecuteAsync()
                .ConfigureAwait(false);

            Assert.IsNotNull(authResult.AccessToken);
        }

        [TestMethod]
        public async Task FailedAuthorityValidationTestAsync()
        {
            LabResponse labResponse = await LabUserHelper.GetDefaultUserAsync().ConfigureAwait(false);
            LabUser user = labResponse.User;

            IPublicClientApplication pca = PublicClientApplicationBuilder
                .Create(labResponse.AppId)
                .WithAuthority("https://bogus.microsoft.com/common")
                .Build();

            Trace.WriteLine("Acquire a token using a not so common authority alias");

            MsalServiceException exception = await AssertException.TaskThrowsAsync<MsalServiceException>(() =>
                 pca.AcquireTokenByUsernamePassword(
                    s_scopes,
                     user.Upn,
                     new NetworkCredential("", user.GetOrFetchPassword()).SecurePassword)
                     .ExecuteAsync())
                .ConfigureAwait(false);

            Assert.IsTrue(exception.Message.Contains("AADSTS50049"));
            Assert.AreEqual("invalid_instance", exception.ErrorCode);
        }

        /// <summary>
        /// If this test fails, please update the <see cref="KnownMetadataProvider"/> to 
        /// use whatever Evo uses (i.e. the aliases, preferred network / metadata from the url below).
        /// </summary>
        [TestMethod]
        public async Task KnownInstanceMetadataIsUpToDateAsync()
        {
            string validDiscoveryUri = @"https://login.microsoftonline.com/common/discovery/instance?api-version=1.1&authorization_endpoint=https%3A%2F%2Flogin.microsoftonline.com%2Fcommon%2Foauth2%2Fv2.0%2Fauthorize";
            HttpClient httpClient = new HttpClient();
            HttpResponseMessage discoveryResponse = await httpClient.SendAsync(
                new HttpRequestMessage(
                    HttpMethod.Get,
                    validDiscoveryUri)).ConfigureAwait(false);
            string discoveryJson = await discoveryResponse.Content.ReadAsStringAsync().ConfigureAwait(false);

            InstanceDiscoveryMetadataEntry[] actualMetadata = JsonHelper.DeserializeFromJson<InstanceDiscoveryResponse>(discoveryJson).Metadata;
            var processedMetadata = new Dictionary<string, InstanceDiscoveryMetadataEntry>();
            foreach (InstanceDiscoveryMetadataEntry entry in actualMetadata)
            {
                foreach (var alias in entry.Aliases)
                {
                    processedMetadata[alias] = entry;
                }
            }

            IDictionary<string, InstanceDiscoveryMetadataEntry> expectedMetadata =
                KnownMetadataProvider.GetAllEntriesForTest();

            CoreAssert.AssertDictionariesAreEqual(
                expectedMetadata,
                processedMetadata,
                new InstanceDiscoveryMetadataEntryComparer());
        }
    }

    internal class InstanceDiscoveryMetadataEntryComparer : IEqualityComparer<InstanceDiscoveryMetadataEntry>
    {
        public bool Equals(InstanceDiscoveryMetadataEntry x, InstanceDiscoveryMetadataEntry y)
        {
            return
                 string.Equals(x.PreferredCache, y.PreferredCache, System.StringComparison.OrdinalIgnoreCase) &&
                 string.Equals(x.PreferredNetwork, y.PreferredNetwork, System.StringComparison.OrdinalIgnoreCase) &&
                 Enumerable.SequenceEqual(x.Aliases, y.Aliases);
        }

        public int GetHashCode(InstanceDiscoveryMetadataEntry obj)
        {
            throw new System.NotImplementedException();
        }
    }
}
