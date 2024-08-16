using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.Google;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;
using System.Text.Encodings.Web;
using Newtonsoft.Json;
using static System.Net.WebRequestMethods;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using System.Net.Http.Headers;

namespace GoogleAuthDemo.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class AccountController : ControllerBase
    {
        [HttpGet("getAccessToken")]
        public async Task<IActionResult> GetAccessToken([FromQuery] string code)
        {
            string url = "https://oauth2.googleapis.com/token";

            var dicData = new Dictionary<string, string>
            {
                { "client_id", "197067534110-m8n9bnebbkpf1hacu2oje6ekvj0ckfas.apps.googleusercontent.com" },
                { "client_secret", "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" },
                { "code", code },
                { "grant_type", "authorization_code" },
                { "redirect_uri", "https://localhost:7017/Account/getAccessToken" },
                { "access_type", "offline" } // Request for refresh_token
            };

            try
            {
                using (var client = new HttpClient())
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
            catch (Exception ex)
            {
                return StatusCode(500, new { Message = "An error occurred while retrieving the access token.", Details = ex.Message });
            }
        }

        [HttpGet("/signin-with-google")]
        public IActionResult SignInWithGoogle()
        {
            string response_type = "code";
            string client_id = "197067534110-m8n9bnebbkpf1hacu2oje6ekvj0ckfas.apps.googleusercontent.com";
            string scope = "openid https://www.googleapis.com/auth/userinfo.email ";
            string redirect_uri = UrlEncoder.Default.Encode("https://localhost:7017/Account/getAccessToken");
            string nonce = "Q2k4UWFtMmZ1NjlBNG1oRU1ENnNNRGhx";

            // Construct the URL without line breaks or extra spaces
            string url = $"https://accounts.google.com/o/oauth2/v2/auth?" +
                         $"response_type={response_type}&" +
                         $"client_id={client_id}&" +
                         $"scope={scope}&" +
                         $"redirect_uri={redirect_uri}&" +
                         $"nonce={UrlEncoder.Default.Encode(nonce)}&" +
                         $"access_type=offline&" + // Request for offline access to get a refresh token
                         $"prompt=consent";

            return Redirect(url);
        }

        [HttpGet("getUserEmail")]
        public async Task<IActionResult> GetUserEmail([FromQuery] string accessToken)
        {
            string json = "";
            string url = $"https://www.googleapis.com/oauth2/v2/userinfo?fields=email";

            try
            {
                using (var client = new HttpClient())
                {
                    client.DefaultRequestHeaders.Authorization =
                    new AuthenticationHeaderValue("Bearer", accessToken);

                    HttpResponseMessage response = await client.GetAsync(url);
                    if (response.IsSuccessStatusCode)
                    {
                        json = await response.Content.ReadAsStringAsync();
                        var emailResponse = JsonConvert.DeserializeObject<EmailResponse>(json);
                        return Ok(emailResponse);
                    }
                    else
                    {
                        return BadRequest(new { Message = "Failed to retrieve user email. " });
                    }

                }
            }
            catch (Exception ex)
            {
                return StatusCode(500, new { Message = "An error occurred while retrieving the user email.", Details = ex.Message });
            }
        }

        [HttpPost("renewAccessToken")]
        public async Task<IActionResult> RenewAccessToken([FromBody] string refreshToken)
        {
            string url = "https://oauth2.googleapis.com/token";

            var dicData = new Dictionary<string, string>
            {
                { "client_id", "197067534110-m8n9bnebbkpf1hacu2oje6ekvj0ckfas.apps.googleusercontent.com" },
                { "client_secret", "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" },
                { "refresh_token", refreshToken },
                { "grant_type", "refresh_token" }
            };
            try
            {
                using (var client = new HttpClient())
                using (var content = new FormUrlEncodedContent(dicData))
                {
                    HttpResponseMessage response = await client.PostAsync(url, content);
                    string json = await response.Content.ReadAsStringAsync();

                    var tokenResponse = JsonConvert.DeserializeObject<OAuthTokenResponse>(json);

                    if (tokenResponse.IsSuccess)
                    {
                        // Return the new access token
                        return Ok(new { tokenResponse.access_token, tokenResponse.expires_in });
                    }
                    else
                    {
                        return BadRequest(new { tokenResponse.error, tokenResponse.error_description });
                    }
                }
            }
            catch (Exception ex)
            {
                return StatusCode(500, new { Message = "An error occurred while renewing the access token.", Details = ex.Message });
            }
        }
    public class EmailResponse
        {
            [JsonProperty("email")]
            public string Email { get; set; }
        }

    }
}
