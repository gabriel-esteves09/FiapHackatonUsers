namespace FHCK_Users.Application.Result;

public class AuthenticationResult
{
    public bool Success { get; set; }
    public string? Token { get; set; }
    public string? RefreshToken { get; set; }
    public DateTime Expiration { get; set; }

    public AuthenticationResult() { }

    public AuthenticationResult(bool success, string? token, string? refreshToken, DateTime expiration)
    {
        Success = success;
        Token = token;
        RefreshToken = refreshToken;
        Expiration = expiration;
    }
}
