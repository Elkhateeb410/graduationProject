using System.ComponentModel.DataAnnotations;

namespace graduationProject.DTOs
{
    public class UserViewDto
    {
        public string Id { get; set; }
        public IEnumerable<string> Roles { get; set; }
        [Required]
        public string FirstName { get; set; }
        [Required]
        public string LastName { get; set; }
        [Required]
        [EmailAddress]
        public string Email { get; set; }
        [Required]
        public string UserName { get; set; }

    }
}
