
using System;
using System.IO;
using System.Security.Claims;
using System.Text;
using System.Text.Encodings.Web;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace dotnetcore3app.AuthenticationHandlers
{
    // https://referbruv.com/blog/posts/implementing-custom-authentication-scheme-and-handler-in-aspnet-core-3x
    public class MyAccountAuthenticationSchemeOptions
        : AuthenticationSchemeOptions
    { }

    public class MyAccountAuthenticationHandler
        : AuthenticationHandler<MyAccountAuthenticationSchemeOptions>
    {
        public MyAccountAuthenticationHandler(
            IOptionsMonitor<MyAccountAuthenticationSchemeOptions> options,
            ILoggerFactory logger,
            UrlEncoder encoder,
            ISystemClock clock)
            : base(options, logger, encoder, clock)
        {
        }

        protected override Task<AuthenticateResult> HandleAuthenticateAsync()
        {
            TokenModel model = new TokenModel();

            // validation comes in here
            if (!Request.Headers.ContainsKey("X-Token"))
            {
                return Task.FromResult(AuthenticateResult.Fail("Header Not Found."));
            }

            var token = Request.Headers["X-Token"].ToString();

            if (token == "barralibre")
            {
                model.EmailAddress = "barralibre@gmail.com";
                model.Name = "nombreBarraLibre";
                model.UserId = 1234;
            }

            if (model != null)
            {
                // success case AuthenticationTicket generation
                // happens from here

                // create claims array from the model
                var claims = new[] {
                    new Claim(ClaimTypes.NameIdentifier, model.UserId.ToString()),
                    new Claim(ClaimTypes.Email, model.EmailAddress),
                    new Claim(ClaimTypes.Name, model.Name) };

                // generate claimsIdentity on the name of the class
                var claimsIdentity = new ClaimsIdentity(claims,
                            nameof(MyAccountAuthenticationHandler));

                // generate AuthenticationTicket from the Identity
                // and current authentication scheme
                // Construyen objetos AuthenticationTicket que representan la identidad del usuario 
                // si la autenticación se realiza correctamente.
                var ticket = new AuthenticationTicket(
                    new ClaimsPrincipal(claimsIdentity), this.Scheme.Name);

                // pass on the ticket to the middleware
                return Task.FromResult(AuthenticateResult.Success(ticket));
            }

            return Task.FromResult(AuthenticateResult.Fail("Model is Empty"));
        }
    }

    public class TokenModel
    {
        public int UserId { get; set; }
        public string Name { get; set; }
        public string EmailAddress { get; set; }
    }
}
