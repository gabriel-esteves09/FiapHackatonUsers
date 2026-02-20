using FHCK_Users.Application.DTO;
using FHCK_Users.Application.Result;
using Microsoft.AspNetCore.Identity;


namespace FHCK_Users.Application.Interface;

public interface IUserService
{
    Task<IdentityResult> RegisterAsync(RegisterDTO model);
    Task<AuthenticationResult> LoginAsync(LoginDTO model);
    Task<IdentityResult> AddRoleAsync(string role);
    Task<IdentityResult> AssignRoleAsync(UserRoleDTO model);
}
