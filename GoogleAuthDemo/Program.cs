using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.Google;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authentication.MicrosoftAccount;
using Microsoft.Identity.Web;


var builder = WebApplication.CreateBuilder(args);

// Add services to the container.

builder.Services.AddControllers();
builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = CookieAuthenticationDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = GoogleDefaults.AuthenticationScheme;
    options.DefaultSignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
})
       .AddCookie()
       .AddGoogle(GoogleDefaults.AuthenticationScheme, options =>
       {
           options.ClientId = "197067534110-m8n9bnebbkpf1hacu2oje6ekvj0ckfas.apps.googleusercontent.com";
           options.ClientSecret = "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";
       })
       .AddMicrosoftAccount(MicrosoftAccountDefaults.AuthenticationScheme, options =>
       {
           options.ClientId = "65891a3d-bcc4-47af-beb2-6cff844ce15d";
           options.ClientSecret = "pYe8Q~syS2YMHptU3IqWQYTCHQbrpankvBekTcgO";
       });

// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();
builder.Services.AddDistributedMemoryCache();
builder.Services.AddSession(options =>
{
    options.IdleTimeout = TimeSpan.FromMinutes(30);
    options.Cookie.HttpOnly = true;
    options.Cookie.IsEssential = true;
});

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();
// Enable authentication and authorization middleware
app.UseAuthentication();
app.UseAuthorization();

app.UseSession();
app.MapControllers();

app.Run();
