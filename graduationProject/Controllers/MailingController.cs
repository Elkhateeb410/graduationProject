using graduationProject.DTOs;
using graduationProject.Services;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace graduationProject.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class MailingController : ControllerBase
    {
        private readonly IMailingService _mailingService;

        public MailingController(IMailingService mailingService)
        {
            _mailingService = mailingService;
        }

        [HttpPost("SendEmail")]
        public async Task<IActionResult> SendEmail([FromForm] MailRequestDto request)
        {
            try
            {
                await _mailingService.SendEmailAsync(request.MailTo, request.Subject, request.Content, request.Attachments);
                return Ok("Email sent Successfully");
            }
            catch (Exception ex)
            {
                throw;
            }
        }
    }
}
