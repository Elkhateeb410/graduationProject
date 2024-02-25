using graduationProject.DTOs;
using graduationProject.Models;

namespace graduationProject.Services
{
    public interface IAuthService
    {
        Task<RegisterResultDto> RegisterAsync(RegisterModel model);
        Task<ResultDto> ConfirmNewEmailAsync(string Id, string newEmail, string Token);
    }
}
