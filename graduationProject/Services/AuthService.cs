using graduationProject.core.Dtos;
using graduationProject.DTOs;
using graduationProject.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Infrastructure;
using Microsoft.AspNetCore.Mvc.Routing;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Options;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace graduationProject.Services
{
    public class AuthService:IAuthService
    {
        private readonly UserManager<IdentityUser> _userManager;
        //private readonly JWT _jwt;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly IMailingService _mailingService;
        private readonly IHttpContextAccessor _httpContextAccessor;
        private readonly IActionContextAccessor _actionContextAccessor;
        private readonly IUrlHelperFactory _urlHelperFactory;

        public AuthService(UserManager<IdentityUser> userManager,/* IOptions<JWT> jwt, */RoleManager<IdentityRole> roleManager, IMailingService mailingService, IHttpContextAccessor httpContextAccessor, IActionContextAccessor actionContextAccessor, IUrlHelperFactory urlHelperFactory)
        {
            _userManager = userManager;
          //  _jwt = jwt.Value;
            _roleManager = roleManager;
            _mailingService = mailingService;
            _httpContextAccessor = httpContextAccessor;
            _actionContextAccessor = actionContextAccessor;
            _urlHelperFactory = urlHelperFactory;
        }

        public async Task<RegisterResultDto> RegisterAsync(RegisterModel model)
        {
            if (await _userManager.FindByEmailAsync(model.Email) is not null)
                return new RegisterResultDto { Message = "The Email Is Already Registered" };
            if (await _userManager.FindByNameAsync(model.UserName) is not null)
                return new RegisterResultDto { Message = "The UserName Is Already Registerd" };
            var user = new IdentityUser
            {
                UserName = model.UserName,
                Email = model.Email,
             //   FirstName = model.FirstName,
               // LastName = model.LastName,
                EmailConfirmed = false
            };
            var result = await _userManager.CreateAsync(user, model.Password);
            if (!result.Succeeded)
            {
                var errors = string.Empty;
                foreach (var error in result.Errors)
                {
                    errors += $"{error.Description},";
                }
                return new RegisterResultDto { Message = errors };
            }
            if (model.IsInvestor)
                await _userManager.AddToRoleAsync(user, "Investor");
            else
                await _userManager.AddToRoleAsync(user, "User");
            var Code = await _userManager.GenerateEmailConfirmationTokenAsync(user);
            var encodedEmailToken = Encoding.UTF8.GetBytes(Code);
            var validEmailToken = WebEncoders.Base64UrlEncode(encodedEmailToken);
            var urlHelper = _urlHelperFactory.GetUrlHelper(_actionContextAccessor.ActionContext);
            var link = urlHelper.Action("ConfirmEmail", "Auth", new { userId = user.Id, code = validEmailToken }, _httpContextAccessor.HttpContext.Request.Scheme);
            //var callbackUrl = $"https://localhost:7298/api/auth/Confirmemail?userId={user.Id}&code={Code}";
            //var callbackUrl = _httpContextAccessor.HttpContext.Request.Scheme+"://"+_httpContextAccessor.HttpContext.Request.Host+urlHelper.Action("ConfirmEmail", "AuthController", new { userId = user.Id, code = Code });
            var message = new MailRequestDto
            {
                MailTo = user.Email,
                Subject = "Confirm Your Email",
                Content = $"Please confirm your email by clicking this link: <a href='{link}'>link</a>",
            };
            var mailResult = await _mailingService.SendEmailAsync(message.MailTo, message.Subject, message.Content);
            if (mailResult)
            {
                return new RegisterResultDto { Message = "Please verify your email ,through the verification email we have just sent", Success = true };
            }
            return new RegisterResultDto { Message = "Something went wrong" };

            //await _userManager.AddToRoleAsync(user, "Moderator");

            //var jwtSecurityToken = await CreateToken(user);
            //var token = new JwtSecurityTokenHandler().WriteToken(jwtSecurityToken);
            //var refreshToken = GenerateRefreshToken();
            //user.RefreshTokens.Add(refreshToken);
            //await _userManager.UpdateAsync(user);
            //return new AuthModel
            //{
            //    IsAuthenticated = true,
            //    Email = user.Email,
            //    UserName = user.UserName,
            //    Token = token,
            //    //ExpiresOn = jwtSecurityToken.ValidTo, // this is not needed because we are using refresh token expiration
            //    Roles = jwtSecurityToken.Claims.Where(x => x.Type == ClaimTypes.Role).Select(x => x.Value).ToList(),
            //    RefreshTokenExpiration = refreshToken.ExpiresOn,
            //    RefreshToken = refreshToken.Token

            //};

        }
        public async Task<ResultDto> ConfirmNewEmailAsync(string Id, string newEmail, string Token)
        {
            
            if (string.IsNullOrEmpty(Id) || string.IsNullOrEmpty(Token))
              {
               return new ResultDto { IsSuccess = false ,Message= "Invalid Email Confirmation Url"
            
               };  
            }
            var user = await _userManager.FindByIdAsync(Id);
            var decodedToken = WebEncoders.Base64UrlDecode(Token);
            var normalToken = Encoding.UTF8.GetString(decodedToken);
            var result = await _userManager.ChangeEmailAsync(user, newEmail, normalToken);
            if (!result.Succeeded)
            {
                return new ResultDto
                {
                    IsSuccess = false,
                    Message = "Invalid Email Confirmation process"

                };
            }
            return new ResultDto
            {

                IsSuccess = true,
                Message = "Email Confirmed Successfully"
            };
           
        }
    }
}
