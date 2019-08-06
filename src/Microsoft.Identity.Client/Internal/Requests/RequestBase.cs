// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using Microsoft.Identity.Client.ApiConfig.Parameters;
using Microsoft.Identity.Client.Cache;
using Microsoft.Identity.Client.Core;
using Microsoft.Identity.Client.Instance;
using Microsoft.Identity.Client.TelemetryCore.Internal;
using Microsoft.Identity.Client.OAuth2;
using Microsoft.Identity.Client.Utils;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Identity.Client.Cache.Items;
using Microsoft.Identity.Client.TelemetryCore.Internal.Events;
using Microsoft.Identity.Client.Instance.Discovery;
using Microsoft.Identity.Json.Linq;
using Microsoft.Identity.Client.Internal.PoP;
using System.Text;
using Microsoft.Identity.Json;

namespace Microsoft.Identity.Client.Internal.Requests
{
    /// <summary>
    /// Base class for all flows. Use by implementing <see cref="ExecuteAsync(CancellationToken)"/>
    /// and optionally calling protected helper methods such as SendTokenRequestAsync, which know
    /// how to use all params when making the request.
    /// </summary>
    internal abstract class RequestBase
    {
        internal AuthenticationRequestParameters AuthenticationRequestParameters { get; }
        internal ICacheSessionManager CacheManager => AuthenticationRequestParameters.CacheSessionManager;
        protected IServiceBundle ServiceBundle { get; }

        protected RequestBase(
            IServiceBundle serviceBundle,
            AuthenticationRequestParameters authenticationRequestParameters,
            IAcquireTokenParameters acquireTokenParameters)
        {
            ServiceBundle = serviceBundle ??
                throw new ArgumentNullException(nameof(serviceBundle));

            AuthenticationRequestParameters = authenticationRequestParameters ??
                throw new ArgumentNullException(nameof(authenticationRequestParameters));

            if (acquireTokenParameters == null)
            {
                throw new ArgumentNullException(nameof(acquireTokenParameters));
            }

            if (authenticationRequestParameters.Scope == null || authenticationRequestParameters.Scope.Count == 0)
            {
                throw new ArgumentNullException(nameof(authenticationRequestParameters.Scope));
            }

            ValidateScopeInput(authenticationRequestParameters.Scope);

            acquireTokenParameters.LogParameters(AuthenticationRequestParameters.RequestContext.Logger);
        }

        private void LogRequestStarted(AuthenticationRequestParameters authenticationRequestParameters)
        {
            string messageWithPii = string.Format(
                CultureInfo.InvariantCulture,
                "=== Token Acquisition ({4}) started:\n\tAuthority: {0}\n\tScope: {1}\n\tClientId: {2}\n\tCache Provided: {3}",
                authenticationRequestParameters.AuthorityInfo?.CanonicalAuthority,
                authenticationRequestParameters.Scope.AsSingleString(),
                authenticationRequestParameters.ClientId,
                CacheManager.HasCache,
                GetType().Name);

            string messageWithoutPii = string.Format(
                CultureInfo.InvariantCulture,
                "=== Token Acquisition ({1}) started:\n\tCache Provided: {0}",
                CacheManager.HasCache,
                GetType().Name);

            if (authenticationRequestParameters.AuthorityInfo != null &&
                KnownMetadataProvider.IsKnownEnvironment(authenticationRequestParameters.AuthorityInfo?.Host))
            {
                messageWithoutPii += string.Format(
                    CultureInfo.CurrentCulture,
                    "\n\tAuthority Host: {0}",
                    authenticationRequestParameters.AuthorityInfo?.Host);
            }

            authenticationRequestParameters.RequestContext.Logger.InfoPii(messageWithPii, messageWithoutPii);
        }

        protected SortedSet<string> GetDecoratedScope(SortedSet<string> inputScope)
        {
            SortedSet<string> set = new SortedSet<string>(inputScope.ToArray());
            set.UnionWith(ScopeHelper.CreateSortedSetFromEnumerable(OAuth2Value.ReservedScopes));
            return set;
        }

        protected void ValidateScopeInput(SortedSet<string> scopesToValidate)
        {
            // Check if scope or additional scope contains client ID.
            // TODO: instead of failing in the validation, could we simply just remove what the user sets and log that we did so instead?
            if (scopesToValidate.Intersect(ScopeHelper.CreateSortedSetFromEnumerable(OAuth2Value.ReservedScopes)).Any())
            {
                throw new ArgumentException("MSAL always sends the scopes 'openid profile offline_access'. " +
                                            "They cannot be suppressed as they are required for the " +
                                            "library to function. Do not include any of these scopes in the scope parameter.");
            }

            if (scopesToValidate.Contains(AuthenticationRequestParameters.ClientId))
            {
                throw new ArgumentException("API does not accept client id as a user-provided scope");
            }
        }

        internal abstract Task<AuthenticationResult> ExecuteAsync(CancellationToken cancellationToken);

        internal virtual Task PreRunAsync()
        {
            return Task.FromResult(0);
        }

        public async Task<AuthenticationResult> RunAsync(CancellationToken cancellationToken)
        {
            ApiEvent apiEvent = InitializeApiEvent(AuthenticationRequestParameters.Account?.HomeAccountId?.Identifier);

            using (ServiceBundle.TelemetryManager.CreateTelemetryHelper(apiEvent))
            {
                try
                {
                    await PreRunAsync().ConfigureAwait(false);
                    AuthenticationRequestParameters.LogParameters(AuthenticationRequestParameters.RequestContext.Logger);
                    LogRequestStarted(AuthenticationRequestParameters);

                    AuthenticationResult authenticationResult = await ExecuteAsync(cancellationToken).ConfigureAwait(false);
                    LogReturnedToken(authenticationResult);

                    apiEvent.TenantId = authenticationResult.TenantId;
                    apiEvent.AccountId = authenticationResult.UniqueId;
                    apiEvent.WasSuccessful = true;
                    return authenticationResult;
                }
                catch (MsalException ex)
                {
                    apiEvent.ApiErrorCode = ex.ErrorCode;
                    AuthenticationRequestParameters.RequestContext.Logger.ErrorPii(ex);
                    throw;
                }
                catch (Exception ex)
                {
                    AuthenticationRequestParameters.RequestContext.Logger.ErrorPii(ex);
                    throw;
                }
                finally
                {
                    ServiceBundle.TelemetryManager.Flush(AuthenticationRequestParameters.RequestContext.CorrelationId.AsMatsCorrelationId());
                }
            }
        }

        protected virtual void EnrichTelemetryApiEvent(ApiEvent apiEvent)
        {
            // In base classes have them override this to add their properties/fields to the event.
        }

        private ApiEvent InitializeApiEvent(string accountId)
        {
            ApiEvent apiEvent = new ApiEvent(
                AuthenticationRequestParameters.RequestContext.Logger,
                ServiceBundle.PlatformProxy.CryptographyManager,
                AuthenticationRequestParameters.RequestContext.CorrelationId.AsMatsCorrelationId())
            {
                ApiId = AuthenticationRequestParameters.ApiId,
                ApiTelemId = AuthenticationRequestParameters.ApiTelemId,
                AccountId = accountId ?? "",
                WasSuccessful = false
            };

            foreach (var kvp in AuthenticationRequestParameters.GetApiTelemetryFeatures())
            {
                apiEvent[kvp.Key] = kvp.Value;
            }

            if (AuthenticationRequestParameters.AuthorityInfo != null)
            {
                apiEvent.Authority = new Uri(AuthenticationRequestParameters.AuthorityInfo.CanonicalAuthority);
                apiEvent.AuthorityType = AuthenticationRequestParameters.AuthorityInfo.AuthorityType.ToString();
            }

            // Give derived classes the ability to add or modify fields in the telemetry as needed.
            EnrichTelemetryApiEvent(apiEvent);

            return apiEvent;
        }

        protected async Task<AuthenticationResult> CacheTokenResponseAndCreateAuthenticationResultAsync(MsalTokenResponse msalTokenResponse)
        {
            // developer passed in user object.
            AuthenticationRequestParameters.RequestContext.Logger.Info("Checking client info returned from the server..");

            ClientInfo fromServer = null;

            if (!AuthenticationRequestParameters.IsClientCredentialRequest &&
                !AuthenticationRequestParameters.IsRefreshTokenRequest &&
                AuthenticationRequestParameters.AuthorityInfo.AuthorityType != AuthorityType.Adfs)
            {
                //client_info is not returned from client credential flows because there is no user present.
                fromServer = ClientInfo.CreateFromJson(msalTokenResponse.ClientInfo);
            }

            ValidateAccountIdentifiers(fromServer);

            IdToken idToken = IdToken.Parse(msalTokenResponse.IdToken);

            AuthenticationRequestParameters.TenantUpdatedCanonicalAuthority =
                   AuthenticationRequestParameters.Authority.GetTenantedAuthority(idToken?.TenantId);

            if (CacheManager.HasCache)
            {
                AuthenticationRequestParameters.RequestContext.Logger.Info("Saving Token Response to cache..");

                var tuple = await CacheManager.SaveTokenResponseAsync(msalTokenResponse).ConfigureAwait(false);
                return new AuthenticationResult(tuple.Item1, tuple.Item2, AuthenticationRequestParameters.RequestContext.CorrelationId);
            }
            else
            {
                return new AuthenticationResult(
                    new MsalAccessTokenCacheItem(
                        AuthenticationRequestParameters.AuthorityInfo.Host,
                        AuthenticationRequestParameters.ClientId,
                        msalTokenResponse,
                        idToken?.TenantId),
                    new MsalIdTokenCacheItem(
                        AuthenticationRequestParameters.AuthorityInfo.Host,
                        AuthenticationRequestParameters.ClientId,
                        msalTokenResponse,
                        idToken?.TenantId),
                        AuthenticationRequestParameters.RequestContext.CorrelationId
                    );
            }
        }

        private void ValidateAccountIdentifiers(ClientInfo fromServer)
        {
            if (fromServer == null || AuthenticationRequestParameters?.Account?.HomeAccountId == null)
            {
                return;
            }

            if (AuthenticationRequestParameters.AuthorityInfo.AuthorityType == AuthorityType.B2C &&
                fromServer.UniqueTenantIdentifier.Equals(AuthenticationRequestParameters.Account.HomeAccountId.TenantId,
                    StringComparison.OrdinalIgnoreCase))
            {
                return;
            }

            if (fromServer.UniqueObjectIdentifier.Equals(AuthenticationRequestParameters.Account.HomeAccountId.ObjectId,
                    StringComparison.OrdinalIgnoreCase) &&
                fromServer.UniqueTenantIdentifier.Equals(AuthenticationRequestParameters.Account.HomeAccountId.TenantId,
                    StringComparison.OrdinalIgnoreCase))
            {
                return;
            }

            AuthenticationRequestParameters.RequestContext.Logger.Error("Returned user identifiers do not match the sent user identifier");

            AuthenticationRequestParameters.RequestContext.Logger.ErrorPii(
                string.Format(
                    CultureInfo.InvariantCulture,
                    "Returned user identifiers (uid:{0} utid:{1}) does not match the sent user identifier (uid:{2} utid:{3})",
                    fromServer.UniqueObjectIdentifier,
                    fromServer.UniqueTenantIdentifier,
                    AuthenticationRequestParameters.Account.HomeAccountId.ObjectId,
                    AuthenticationRequestParameters.Account.HomeAccountId.TenantId),
                string.Empty);

            throw new MsalClientException(MsalError.UserMismatch, MsalErrorMessage.UserMismatchSaveToken);
        }

        internal async Task ResolveAuthorityEndpointsAsync()
        {
            // This will make a network call unless instance discovery is cached, but this ok
            // GetAccounts and AcquireTokenSilent do not need this
            await UpdateAuthorityWithPreferredNetworkHostAsync().ConfigureAwait(false);

            AuthenticationRequestParameters.Endpoints = await ServiceBundle.AuthorityEndpointResolutionManager.ResolveEndpointsAsync(
                AuthenticationRequestParameters.AuthorityInfo,
                AuthenticationRequestParameters.LoginHint,
                AuthenticationRequestParameters.RequestContext).ConfigureAwait(false);
        }


        protected Task<MsalTokenResponse> SendTokenRequestAsync(
            IDictionary<string, string> additionalBodyParameters,
            CancellationToken cancellationToken)
        {
            return SendTokenRequestAsync(
                AuthenticationRequestParameters.Endpoints.TokenEndpoint,
                additionalBodyParameters,
                cancellationToken);
        }

#if NET_CORE
        private static string CreateJwkClaim(string keyId, string algorithm) // TODO: what about optional params like Modulus and Exponent?
        {
            // TODO: original SAL code that shows how to get other params
            //var parameters = key.Rsa == null ? key.Parameters : key.Rsa.ExportParameters(false);
            //return "{\"kty\":\"RSA\",\"n\":\"" + Base64UrlEncoder.Encode(parameters.Modulus) + "\",\"e\":\"" + Base64UrlEncoder.Encode(parameters.Exponent) + "\",\"alg\":\"" + algorithm + "\",\"kid\":\"" + key.KeyId + "\"}";


            // return "{\"kty\":\"RSA\",\"alg\":\"" + algorithm + "\",\"kid\":\"" + keyId + "\"}";
            return "{\"kid\":\"" + keyId + "\"}";

        }

        private static string CreateCnfRequest(IPoPCryptoProvider popCryptoProvider)
        {
            var header = new JObject
            {
                { "typ", "jwt"},
                { "alg" , popCryptoProvider.Algorithm },
                { "kid", popCryptoProvider.KeyId }
            };

            string jwk = popCryptoProvider.CreateJwkClaim();
            var payload = new JObject
            {
                {"jwk", JObject.Parse(jwk)}
            };

            string s = payload.ToString(Formatting.None);

            return CreateJWS(popCryptoProvider, payload.ToString(Formatting.None), header.ToString(Formatting.None));
        }

        private static string CreateJWS(IPoPCryptoProvider popCryptoProvider, string payload, string header)
        {
            var message = Base64UrlEncoder.Encode(Encoding.UTF8.GetBytes(header)) + "." + Base64UrlEncoder.Encode(payload);
            return message + "." + Base64UrlEncoder.Encode(popCryptoProvider.Sign(Encoding.UTF8.GetBytes(message)));
        }

       

#endif

        protected async Task<MsalTokenResponse> SendTokenRequestAsync(
            string tokenEndpoint,
            IDictionary<string, string> additionalBodyParameters,
            CancellationToken cancellationToken)
        {
            OAuth2Client client = new OAuth2Client(ServiceBundle.DefaultLogger, ServiceBundle.HttpManager, ServiceBundle.TelemetryManager);
            client.AddBodyParameter(OAuth2Parameter.ClientId, AuthenticationRequestParameters.ClientId);
            client.AddBodyParameter(OAuth2Parameter.ClientInfo, "1");

            // TODO: ideally, this can come from the particular request instance and not be in RequestBase since it's not valid for all requests.

#if NET_CORE
            if (AuthenticationRequestParameters.AuthenticationScheme == AuthenticationScheme.PoP)
            {
                string kid = AuthenticationRequestParameters.PoPCryptoProvider.KeyId;
                string algorithm = AuthenticationRequestParameters.PoPCryptoProvider.Algorithm;

                //client.AddBodyParameter("pop_jwk", CreateJwkClaim(kid, algorithm));
                client.AddBodyParameter("req_cnf", CreateCnfRequest(AuthenticationRequestParameters.PoPCryptoProvider));

                client.AddBodyParameter("token_type", "pop");
            }
#endif


#if DESKTOP || NETSTANDARD1_3 || NET_CORE
            if (AuthenticationRequestParameters.ClientCredential != null)
            {
                Dictionary<string, string> ccBodyParameters = ClientCredentialHelper.CreateClientCredentialBodyParameters(
                    AuthenticationRequestParameters.RequestContext.Logger,
                    ServiceBundle.PlatformProxy.CryptographyManager,
                    AuthenticationRequestParameters.ClientCredential,
                    AuthenticationRequestParameters.ClientId,
                    AuthenticationRequestParameters.Endpoints,
                    AuthenticationRequestParameters.SendX5C);

                foreach (var entry in ccBodyParameters)
                {
                    client.AddBodyParameter(entry.Key, entry.Value);
                }
            }
#endif

            client.AddBodyParameter(OAuth2Parameter.Scope,
                GetDecoratedScope(AuthenticationRequestParameters.Scope).AsSingleString());

            client.AddQueryParameter(OAuth2Parameter.Claims, AuthenticationRequestParameters.Claims);

            foreach (var kvp in additionalBodyParameters)
            {
                client.AddBodyParameter(kvp.Key, kvp.Value);
            }

            return await SendHttpMessageAsync(client, tokenEndpoint).ConfigureAwait(false);
        }


        private async Task<MsalTokenResponse> SendHttpMessageAsync(OAuth2Client client, string tokenEndpoint)
        {
            UriBuilder builder = new UriBuilder(tokenEndpoint);
            builder.AppendQueryParameters(AuthenticationRequestParameters.ExtraQueryParameters);
            MsalTokenResponse msalTokenResponse =
                await client
                    .GetTokenAsync(builder.Uri,
                        AuthenticationRequestParameters.RequestContext)
                    .ConfigureAwait(false);

            if (string.IsNullOrEmpty(msalTokenResponse.Scope))
            {
                msalTokenResponse.Scope = AuthenticationRequestParameters.Scope.AsSingleString();
                AuthenticationRequestParameters.RequestContext.Logger.Info("ScopeSet was missing from the token response, so using developer provided scopes in the result");
            }

            return msalTokenResponse;
        }

        private void LogReturnedToken(AuthenticationResult result)
        {
            if (result.AccessToken != null)
            {
                AuthenticationRequestParameters.RequestContext.Logger.Info(
                    string.Format(
                        CultureInfo.InvariantCulture,
                        "=== Token Acquisition finished successfully. An access token was returned with Expiration Time: {0} ===",
                        result.ExpiresOn));
            }
        }

        private async Task UpdateAuthorityWithPreferredNetworkHostAsync()
        {
            InstanceDiscoveryMetadataEntry metadata = await
                ServiceBundle.InstanceDiscoveryManager.GetMetadataEntryAsync(
                    AuthenticationRequestParameters.AuthorityInfo.CanonicalAuthority,
                    AuthenticationRequestParameters.RequestContext)
                .ConfigureAwait(false);

            AuthenticationRequestParameters.AuthorityInfo.CanonicalAuthority =
                Authority.CreateAuthorityWithEnvironment(
                    AuthenticationRequestParameters.AuthorityInfo.CanonicalAuthority,
                    metadata.PreferredNetwork);
        }

    }

    public static class Base64UrlEncoder
    {
        private static char base64PadCharacter = '=';
        private static string doubleBase64PadCharacter = "==";
        private static char base64Character62 = '+';
        private static char base64Character63 = '/';
        private static char base64UrlCharacter62 = '-';
        private static char _base64UrlCharacter63 = '_';

        /// <summary>
        /// The following functions perform base64url encoding which differs from regular base64 encoding as follows
        /// * padding is skipped so the pad character '=' doesn't have to be percent encoded
        /// * the 62nd and 63rd regular base64 encoding characters ('+' and '/') are replace with ('-' and '_')
        /// The changes make the encoding alphabet file and URL safe.
        /// </summary>
        /// <param name="arg">string to encode.</param>
        /// <returns>Base64Url encoding of the UTF8 bytes.</returns>
        public static string Encode(string arg)
        {

            return Encode(Encoding.UTF8.GetBytes(arg));
        }

        /// <summary>
        /// Converts a subset of an array of 8-bit unsigned integers to its equivalent string representation that is encoded with base-64-url digits. Parameters specify
        /// the subset as an offset in the input array, and the number of elements in the array to convert.
        /// </summary>
        /// <param name="inArray">An array of 8-bit unsigned integers.</param>
        /// <param name="length">An offset in inArray.</param>
        /// <param name="offset">The number of elements of inArray to convert.</param>
        /// <returns>The string representation in base 64 url encodingof length elements of inArray, starting at position offset.</returns>
        /// <exception cref="ArgumentNullException">'inArray' is null.</exception>
        /// <exception cref="ArgumentOutOfRangeException">offset or length is negative OR offset plus length is greater than the length of inArray.</exception>
        public static string Encode(byte[] inArray, int offset, int length)
        {

            string s = Convert.ToBase64String(inArray, offset, length);
            s = s.Split(base64PadCharacter)[0]; // Remove any trailing padding
            s = s.Replace(base64Character62, base64UrlCharacter62);  // 62nd char of encoding
            s = s.Replace(base64Character63, _base64UrlCharacter63);  // 63rd char of encoding
            return s;
        }

        /// <summary>
        /// Converts a subset of an array of 8-bit unsigned integers to its equivalent string representation that is encoded with base-64-url digits. Parameters specify
        /// the subset as an offset in the input array, and the number of elements in the array to convert.
        /// </summary>
        /// <param name="inArray">An array of 8-bit unsigned integers.</param>
        /// <returns>The string representation in base 64 url encodingof length elements of inArray, starting at position offset.</returns>
        /// <exception cref="ArgumentNullException">'inArray' is null.</exception>
        /// <exception cref="ArgumentOutOfRangeException">offset or length is negative OR offset plus length is greater than the length of inArray.</exception>
        public static string Encode(byte[] inArray)
        {
            string s = Convert.ToBase64String(inArray, 0, inArray.Length);
            s = s.Split(base64PadCharacter)[0]; // Remove any trailing padding
            s = s.Replace(base64Character62, base64UrlCharacter62);  // 62nd char of encoding
            s = s.Replace(base64Character63, _base64UrlCharacter63);  // 63rd char of encoding

            return s;
        }

        /// <summary>
        ///  Converts the specified string, which encodes binary data as base-64-url digits, to an equivalent 8-bit unsigned integer array.</summary>
        /// <param name="str">base64Url encoded string.</param>
        /// <returns>UTF8 bytes.</returns>
        public static byte[] DecodeBytes(string str)
        {
            // 62nd char of encoding
            str = str.Replace(base64UrlCharacter62, base64Character62);

            // 63rd char of encoding
            str = str.Replace(_base64UrlCharacter63, base64Character63);

            // check for padding
            switch (str.Length % 4)
            {
                case 0:
                    // No pad chars in this case
                    break;
                case 2:
                    // Two pad chars
                    str += doubleBase64PadCharacter;
                    break;
                case 3:
                    // One pad char
                    str += base64PadCharacter;
                    break;
            }

            return Convert.FromBase64String(str);
        }

        /// <summary>
        /// Decodes the string from Base64UrlEncoded to UTF8.
        /// </summary>
        /// <param name="arg">string to decode.</param>
        /// <returns>UTF8 string.</returns>
        public static string Decode(string arg)
        {
            return Encoding.UTF8.GetString(DecodeBytes(arg));
        }
    }

}
