using FHCK_Users.Application.DTO;
using FHCK_Users.Application.Interface;
using FHCK_Users.Application.Result;
using FHCK_Users.Domain.Entity;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Configuration;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;

namespace FHCK_Users.Application.Service;

public class UserService : IUserService
{
    private readonly UserManager<User> _userManager;
    private readonly RoleManager<IdentityRole> _roleManager;
    private readonly IConfiguration _configuration;
    private readonly ITokenService _tokenService;

    public UserService(UserManager<User> userManager, RoleManager<IdentityRole> roleManager, IConfiguration configuration, ITokenService tokenService)
    {
        _userManager = userManager;
        _roleManager = roleManager;
        _configuration = configuration;
        _tokenService = tokenService;
    }

    public async Task<IdentityResult> RegisterAsync(RegisterDTO model)
    {
        var user = new User { UserName = model.Username, Email = model.Email };
        var result = await _userManager.CreateAsync(user, model.Password);

        if (result.Succeeded)
        {
            var roleExist = await _roleManager.RoleExistsAsync("User");

            if (!roleExist)
            {
                var role = new IdentityRole("User");
                await _roleManager.CreateAsync(role);
            }

            await _userManager.AddToRoleAsync(user, "User");
        }

        return result;
    }

    public async Task<AuthenticationResult> LoginAsync(LoginDTO model)
    {
        var user = await _userManager.FindByEmailAsync(model.Email);

        if (user is not null && await _userManager.CheckPasswordAsync(user, model.Password))
        {
            var userRoles = await _userManager.GetRolesAsync(user);

            var authClaims = new List<Claim>
        {
            new Claim(JwtRegisteredClaimNames.Sub, user.Id), // <-- ADICIONA ISSO (OwnerId)
            new Claim(ClaimTypes.Name, user.UserName ?? string.Empty),
            new Claim(ClaimTypes.Email, user.Email ?? string.Empty),
            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
        };

            foreach (var userRole in userRoles)
            {
                authClaims.Add(new Claim(ClaimTypes.Role, userRole));
            }

            var token = _tokenService.GenerateAcessToken(authClaims, _configuration);
            var refreshToken = _tokenService.GenerateRefreshToken();

            _ = int.TryParse(_configuration["JWT:RefreshTokenExpirationInMinutes"], out int refreshTokenValidityInMinutes);

            user.RefreshTokenExpiryTime = DateTime.UtcNow.AddMinutes(refreshTokenValidityInMinutes);
            user.RefreshToken = refreshToken;

            await _userManager.UpdateAsync(user);

            var writtenToken = new JwtSecurityTokenHandler().WriteToken(token);

            return new AuthenticationResult(true, writtenToken, refreshToken, token.ValidTo);
        }

        return new AuthenticationResult(false, null, null, DateTime.MinValue);
    }


    public async Task<IdentityResult> AddRoleAsync(string role)
    {
        if (!await _roleManager.RoleExistsAsync(role))
        {
            var result = await _roleManager.CreateAsync(new IdentityRole(role));
            return result;
        }

        return IdentityResult.Failed(new IdentityError { Description = "Role already exists" });
    }

    public async Task<IdentityResult> AssignRoleAsync(UserRoleDTO model)
    {
        var user = await _userManager.FindByEmailAsync(model.Email);
        if (user == null)
        {
            return IdentityResult.Failed(new IdentityError { Description = "User not found" });
        }

        var result = await _userManager.AddToRoleAsync(user, model.Role);
        return result;
    }
}
