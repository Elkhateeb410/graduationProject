using System.ComponentModel.DataAnnotations;
namespace graduationProject.core.Dtos
{
    public class ChangePasswordDto
    {
       
        [Required(ErrorMessage = "CurrentPassword is required")]
        public string CurrentPassword { get; set; }

        [Required(ErrorMessage = "NewPassword is required")]
        public string NewPassword { get; set; }
    }
}
