using graduationProject.DTOs;

namespace graduationProject.Services
{
    public interface IRoleService
    {
        Task<UserRolesDTO> UpdateUserRoles(UserRolesDTO dto);
        Task<UserRolesDTO> ManageUserRoles(string userId);
        Task<List<UserViewDto>> ViewUsers();

    }
}
