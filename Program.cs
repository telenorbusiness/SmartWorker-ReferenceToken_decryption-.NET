using System;
using System.Collections.Generic;
using System.Security.Cryptography;

namespace ReferenceTokenSample
{
    internal class Program
    {
        private static void Main(string[] args)
        {
            // First a client connects to your endpoint using Authorization: Bearer <some_long_reference_token>
            // Then you pick up this refenceToken, and do a HTTP GET towards https://idp.smartansatt.telenor.no/idp/me in prod or in test https://smartworker-dev-azure-idp.pimdemo.no/idp/me,
            // where you reuse this refenceToken as Authorization Token (Not Bearer, Not Basic, but just the token.
            //  HttpClient client = new HttpClient();
            //  client.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue(referenceToken, string.Empty);
            //  var response = await client.GetAsync("https://idp.smartansatt.telenor.no/idp/me");
          
            // You will then receive a base64 encoded string which you will need to decrypt before you know the identity of the calling user/client
            string receivedJWTfromUserInfoEndpoint = "someRandomBase64Encodedstring.someRandomBase64Encodedstring.someRandomBase64Encodedstring.someRandomBase64Encodedstring.someRandomBase64Encodedstring";

            RunSample_JWE_Signed_Then_Encrypted(receivedJWTfromUserInfoEndpoint);
        }

        private static byte[] FromBase64Url(string base64Url)
        {
            var padded = base64Url.Length % 4 == 0 ? base64Url : base64Url + "====".Substring(base64Url.Length % 4);
            var base64 = padded.Replace("_", "/").Replace("-", "+");
            return Convert.FromBase64String(base64);
        }

        private static void RunSample_JWE_Signed_Then_Encrypted(string receivedJWTfromUserInfoEndpoint)
        {
            // First load Partner certificate with private key to decrypt content
            // If encryption is not enabled, this step is not necesary. Not using JWE
            RSACryptoServiceProvider rsaEnc = new RSACryptoServiceProvider();
            rsaEnc.ImportParameters(
              new RSAParameters()
              {
                  D = FromBase64Url("base64"),
                  DP = FromBase64Url("base64"),
                  DQ = FromBase64Url("base64"),
                  InverseQ = FromBase64Url("base64"),
                  P = FromBase64Url("base64"),
                  Q = FromBase64Url("base64"),
                  Modulus = FromBase64Url("base64"),
                  Exponent = FromBase64Url("base64")
              }
              );

            // Then load signature certificate used for validation of sender
            // If not using JWS or an nested JWT (JWS and JWE)
            // This can be retrieved from:
            // Production:
            // https://idp.smartansatt.telenor.no/.well-known/openid-configuration, where jwks certificates
            // are defined as "jwks_uri":"https://idp.smartansatt.pimdemo.no/idp/certs"
            // Test:
            // https://smartworker-dev-azure-idp.smartansatt.telenor.no/.well-known/openid-configuration, where jwks certificates
            // are defined as "jwks_uri":"https://smartworker-dev-azure-idp.pimdemo.no/idp/certs"
            // Find the correct one by matching "kid" in the cert-list from the one in the JWT/JWS/JWE header received from userinfo endpoint

            RSACryptoServiceProvider rsaSig = new RSACryptoServiceProvider(); // Currently this is the public certificate used in test. 
            rsaSig.ImportParameters(
              new RSAParameters()
              {
                  Modulus = FromBase64Url("hTEb-opJM0BCBF0ijAm3RaUUBV3lDZ7fQNE6xuEbAQj4Ip43yoTO9UcmHoDgE33FOB8WMVlql5ZHiA1NziTe1d-MDzS2YQovc8yqQo4MKcRASAHL7iNj7pVYpP6YXGxWEwU1OYuQBpZNGoNoU5JuFNhBTHf-d0vQf3WTfnhGcfX6ZyDEgXVi97k_JUVdtva2Z1OSzmyh261tZfQg0mSIlC3Q-MdI-pPMXypsEi_cT1LXumnN0UGrAFRxv3xpGcvNrCjD_yiw0CpeXd0g2NGpePNAcReVTDtH9zQ2DFqX3Jt4K7FChHwW3zB7Dv5IuYJ9RKvogImZSdtClx7u-p9PvQ"),
                  Exponent = FromBase64Url("AQAB")
              });

            // This is typically a response from the userinfo endpoint located at the smartansatt IDP.
          
            var header = Jose.JWT.Headers(receivedJWTfromUserInfoEndpoint);
            // The header will contain information regarding which encryption algorithm and kid is used,
            // if the JWT is not encrypted, you will se information regarding signature verifcation
            // Example:
            //		header	Count = 4	System.Collections.Generic.IDictionary<string,object> {System.Collections.Generic.Dictionary<string,object>}
            //		[0]	{[alg, RSA1_5]}	System.Collections.Generic.KeyValuePair<string,object>
            //		[1]	{[kid, LD42-RAChzS8NtAcRBnDjCN_itzLaUqXFOgSZuCWc4s]}	System.Collections.Generic.KeyValuePair<string,object>
            //		[2]	{[enc, A128CBC-HS256]}	System.Collections.Generic.KeyValuePair<string,object>
            //		[3]	{[cty, JWT]}	System.Collections.Generic.KeyValuePair<string,object>

            // If you are unable to decrypt check that the algorithms and details match what you are trying to decrypt
            var decrypted = Jose.JWT.Decode(receivedJWTfromUserInfoEndpoint, rsaEnc, Jose.JweAlgorithm.RSA1_5, Jose.JweEncryption.A128CBC_HS256);

            var signatureheader = Jose.JWT.Headers(decrypted);
            /// 	signatureheader	Count = 3	System.Collections.Generic.IDictionary<string,object> {System.Collections.Generic.Dictionary<string,object>}
            //		[0]	{[alg, RS256]}	System.Collections.Generic.KeyValuePair<string,object>
            //		[1]	{[typ, JWT]}	System.Collections.Generic.KeyValuePair<string,object>
            //		[2]	{[kid, sig-rs-0]}	System.Collections.Generic.KeyValuePair<string,object>

            // Then we validate the payload but verifiying the signature
            var decoded = Jose.JWT.Decode(decrypted, rsaSig, Jose.JwsAlgorithm.RS256);

            Jose.JSSerializerMapper js = new Jose.JSSerializerMapper();
            var json = js.Parse<Dictionary<string, object>>(decoded);
            //    	json	Count = 13	System.Collections.Generic.Dictionary<string,object>
            //		[0]	{[sub, *some_guid*]}	System.Collections.Generic.KeyValuePair<string,object>
            //		[1]	{[phone_number, 12345678]}	System.Collections.Generic.KeyValuePair<string,object>
            //		[2]	{[phone_number_verified, True]}	System.Collections.Generic.KeyValuePair<string,object>
            //		[3]	{[organizationNumber, *secret*]}	System.Collections.Generic.KeyValuePair<string,object>
            //		[4]	{[telenorSsoToken, *secret*]}	System.Collections.Generic.KeyValuePair<string,object>
            //		[5]	{[userRoles, System.Collections.ArrayList]}	System.Collections.Generic.KeyValuePair<string,object>
            //		[6]	{[userId, *some_guid*]}	System.Collections.Generic.KeyValuePair<string,object>
            //		[7]	{[companyId, *some_guid*]}	System.Collections.Generic.KeyValuePair<string,object>
            //		[8]	{[success, True]}	System.Collections.Generic.KeyValuePair<string,object>
            //		[9]	{[iat, 1513605740]}	System.Collections.Generic.KeyValuePair<string,object>
            //		[10]	{[exp, 1513605856]}	System.Collections.Generic.KeyValuePair<string,object>
            //		[11]	{[aud, 0699588b-a1c3-4f13-abf6-6f6c2ece4601]}	System.Collections.Generic.KeyValuePair<string,object>
            //		[12]	{[iss, https://smartworker-dev-azure-idp.pimdemo.no]}	System.Collections.Generic.KeyValuePair<string,object>

            Console.ReadKey();
        }
    }
}