namespace graduationProject.Services
{
    public interface IMailingService
    {
        Task<bool> SendEmailAsync(string mailTo, string subject, string content, IList<IFormFile> attchments = null);
    }
}
