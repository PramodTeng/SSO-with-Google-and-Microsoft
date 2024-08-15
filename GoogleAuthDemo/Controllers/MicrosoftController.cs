using Microsoft.AspNetCore.Mvc;
using Newtonsoft.Json;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Encodings.Web;

namespace GoogleAuthDemo.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class MicrosoftController : ControllerBase
    {
        [HttpPost("getAccessToken")]
        public async Task<IActionResult> GetAccessToken([FromForm] string code)
        {
            string url = "https://login.microsoftonline.com/9cf1f232-1797-4931-be76-52c9187f29cd/oauth2/v2.0/token";

            var dicData = new Dictionary<string, string>
            {
                { "client_id", "65891a3d-bcc4-47af-beb2-6cff844ce15d" },
                { "scope", "api://65891a3d-bcc4-47af-beb2-6cff844ce15d/openid api://65891a3d-bcc4-47af-beb2-6cff844ce15d/Forecast.Read" },
                { "code", code },
                { "redirect_uri", "https://localhost:7017/Microsoft/getAccessToken" },        
                { "grant_type", "authorization_code" },
                { "code_verifier",  "ThisIsntRandomButItNeedsToBe43CharactersLongABCDE"},
                { "client_secret", "pYe8Q~syS2YMHptU3IqWQYTCHQbrpankvBekTcgO" },
            };

            try
            {
                using (var client = new HttpClient())
                {
                    string authHeader = Convert.ToBase64String(Encoding.ASCII.GetBytes("client_id:client_secret"));
                    client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Basic", authHeader);

                    using (var content = new FormUrlEncodedContent(dicData))
                    {
                        HttpResponseMessage response = await client.PostAsync(url, content);
                        string json = await response.Content.ReadAsStringAsync();

                        var tokenResponse = JsonConvert.DeserializeObject<OAuthTokenResponse>(json);

                        if (tokenResponse.IsSuccess)
                        {
                            return Ok(tokenResponse);
                        }
                        else
                        {
                            // Return error response with appropriate message
                            return BadRequest(new { tokenResponse.error, tokenResponse.error_description });
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                return StatusCode(500, new { Message = "An error occurred while retrieving the access token.", Details = ex.Message });
            }
        }

        [HttpGet("/signin-with-microsoft")]
        public IActionResult SignInWithMicroSoft()
        {
            // Generate a random state parameter
            string state = Guid.NewGuid().ToString();

            // Store the state in the session to validate it later
            HttpContext.Session.SetString("OAuthState", state);

            string response_type = "code id_token";
            string client_id = "65891a3d-bcc4-47af-beb2-6cff844ce15d";
            string scope = "api://65891a3d-bcc4-47af-beb2-6cff844ce15d/openid api://65891a3d-bcc4-47af-beb2-6cff844ce15d/Forecast.Read";
            string redirect_uri = UrlEncoder.Default.Encode("https://localhost:7017/Microsoft/getAccessToken");
            string nonce = "Q2k4UWFtMmZ1NjlBNG1oRU1ENnNNRGhx";
            string response_mode = "form_post";

            // Generate code_verifier and code_challenge for PKCE
            string code_verifier = "ThisIsntRandomButItNeedsToBe43CharactersLongABCDE";
            string code_challenge = GenerateCodeChallenge(code_verifier);
            string code_challenge_method = "S256";

            // Store the code_verifier in the session or state to use later when exchanging the authorization code for an access token
            HttpContext.Session.SetString("code_verifier", code_verifier);

            string url = $"https://login.microsoftonline.com/9cf1f232-1797-4931-be76-52c9187f29cd/oauth2/v2.0/authorize?" +
                        $"client_id={client_id}&" +
                        $"response_type={response_type}&" +
                        $"redirect_uri={redirect_uri}&" +
                        $"response_mode={response_mode}&" +
                        $"scope={scope}&" +
                        $"state={UrlEncoder.Default.Encode(state)}&" +
                        $"nonce={UrlEncoder.Default.Encode(nonce)}&" +
                        $"code_challenge={code_challenge}&" +
                        $"code_challenge_method={code_challenge_method}";

            return Redirect(url);
        }
        private string GenerateCodeChallenge(string codeVerifier)
        {
            using (var sha256 = SHA256.Create())
            {
                byte[] challengeBytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(codeVerifier));
                return Convert.ToBase64String(challengeBytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
            }
        }
    }
}
