using graduationProject.DTOs;
using graduationProject.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using System.Security.Principal;

namespace graduationProject.Services
{
    public class RoleService : IRoleService
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        public RoleService(UserManager<IdentityUser> userManager, RoleManager<IdentityRole> roleManager)
        {
            _userManager = userManager;
            _roleManager = roleManager;
        }

        public async Task<UserRolesDTO> UpdateUserRoles(UserRolesDTO dto)
        {
            var user = await _userManager.FindByIdAsync(dto.Id);
            if (user is null)
            {
                dto.ErrorMessage = "No User With This Id";
                return dto;
            }

            var UserRoles = await _userManager.GetRolesAsync(user);
            foreach (var role in dto.Roles)
            {
                if (UserRoles.Any(r => r == role.Name) && !role.IsSelected)
                    await _userManager.RemoveFromRoleAsync(user, role.Name);
                if (!UserRoles.Any(r => r == role.Name) && role.IsSelected)
                    await _userManager.AddToRoleAsync(user, role.Name);
            }

            var roles = await _roleManager.Roles.ToListAsync();

            var UserRolesDto = new UserRolesDTO
            {
                Id = dto.Id,
                UserName = dto.UserName,
                ErrorMessage = string.Empty,
                Roles = roles.Select(r => new RoleModel
                {
                    Id = r.Id,
                    Name = r.Name,
                    IsSelected = _userManager.IsInRoleAsync(user, r.Name).Result
                })
            };
            return UserRolesDto;
        }

        public async Task<UserRolesDTO> ManageUserRoles(string userId)
        {
            var user = await _userManager.FindByIdAsync(userId);
            var userRolesdto = new UserRolesDTO();
            if (user is null)
            {
                userRolesdto.ErrorMessage = "No user with this id";
                return userRolesdto;
            }
            var roles = await _roleManager.Roles.ToListAsync();

            userRolesdto.ErrorMessage = string.Empty;
            userRolesdto.Id = user.Id;
            userRolesdto.UserName = user.UserName;
            userRolesdto.Roles = roles.Select(r => new RoleModel
            {
                Id = r.Id,
                Name = r.Name,
                IsSelected = _userManager.IsInRoleAsync(user, r.Name).Result
            });
            return userRolesdto;
        }

        public async Task<List<UserViewDto>> ViewUsers()
        {
            var users = await _userManager.Users.ToListAsync();

            var userViewModels = users.Select(user => new UserViewDto
            {
                Id = user.Id,
                UserName = user.UserName,
                Email = user.Email,
                Roles = _userManager.GetRolesAsync(user).Result
            }).ToList();

            return userViewModels;
        }

    }
}
