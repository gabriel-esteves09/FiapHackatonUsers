using Microsoft.AspNetCore.Identity;

namespace FHCK_Users.Domain.Entity;

public class User : IdentityUser
{
    public string? RefreshToken { get; set; }
    public DateTime RefreshTokenExpiryTime { get; set; }
}
