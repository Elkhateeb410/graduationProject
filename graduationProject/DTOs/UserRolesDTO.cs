using graduationProject.Models;

namespace graduationProject.DTOs
{
    public class UserRolesDTO
    {
        public string Id { get; set; }
        public string UserName { get; set; }
        public IEnumerable<RoleModel> Roles { get; set; }
        public string ErrorMessage { get; set; }
    }
}
