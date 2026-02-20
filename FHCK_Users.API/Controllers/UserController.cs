using FHCK_Users.Application.DTO;
using FHCK_Users.Application.Interface;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace FHCK_UsersAPI.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class UserController : ControllerBase
    {
        private readonly IUserService _userService;

        public UserController(IUserService userService)
        {
            _userService = userService;
        }

        [HttpPost]
        [Route("Register")]
        public async Task<IActionResult> Register([FromBody] RegisterDTO model)
        {
            var result = await _userService.RegisterAsync(model);

            if (result.Succeeded)
            {
                return Ok(new { message = "User registered successfully" });
            }

            return BadRequest(result.Errors);
        }

        [HttpPost]
        [Route("Login")]
        public async Task<IActionResult> Login([FromBody] LoginDTO model)
        {
            var authResult = await _userService.LoginAsync(model);

            if (authResult.Success)
            {
                return Ok(new
                {
                    Token = authResult.Token,
                    RefreshToken = authResult.RefreshToken,
                    Expiration = authResult.Expiration
                });
            }

            return Unauthorized();
        }

        [Authorize(Roles = "Admin")]
        [HttpPost]
        [Route("AddRole")]
        public async Task<IActionResult> AddRole([FromBody] string role)
        {
            var result = await _userService.AddRoleAsync(role);

            if (result.Succeeded)
            {
                return Ok(new { message = "Role added successfully" });
            }

            return BadRequest(result.Errors);
        }

        [Authorize(Roles = "Admin")]
        [HttpPost]
        [Route("AssignRole")]
        public async Task<IActionResult> AssignRole([FromBody] UserRoleDTO model)
        {
            var result = await _userService.AssignRoleAsync(model);

            if (result.Succeeded)
            {
                return Ok(new { message = "Role assigned successfully" });
            }

            return BadRequest(result.Errors);
        }
    }
}
