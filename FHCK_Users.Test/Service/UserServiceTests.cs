using FHCK_Users.Application.DTO;
using FHCK_Users.Application.Interface;
using FHCK_Users.Application.Result;
using FHCK_Users.Application.Service;
using FHCK_Users.Domain.Entity;
using FHCK_Users.Test.Mocks.DTO;
using FHCK_Users.Test.Mocks.Entity;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Moq;
using NUnit.Framework;

namespace FHCK_Users.Test.Service;

[TestFixture]
public class UserServiceTests
{
    #region Private Fields

    private Mock<UserManager<User>> _userManagerMock;
    private Mock<RoleManager<IdentityRole>> _roleManagerMock;
    private Mock<IConfiguration> _configurationMock;
    private Mock<ITokenService> _tokenServiceMock;

    private UserService _service;

    #endregion

    #region Setup

    [SetUp]
    public void Setup()
    {
        // UserManager mock (precisa de IUserStore)
        var userStoreMock = new Mock<IUserStore<User>>();

        _userManagerMock = new Mock<UserManager<User>>(
            userStoreMock.Object,
            null!, null!, null!, null!, null!, null!, null!, null!
        );

        // RoleManager mock (precisa de IRoleStore)
        var roleStoreMock = new Mock<IRoleStore<IdentityRole>>();

        _roleManagerMock = new Mock<RoleManager<IdentityRole>>(
            roleStoreMock.Object,
            Array.Empty<IRoleValidator<IdentityRole>>(),
            new UpperInvariantLookupNormalizer(),
            new IdentityErrorDescriber(),
            new Mock<ILogger<RoleManager<IdentityRole>>>().Object
        );

        _configurationMock = new Mock<IConfiguration>();
        _tokenServiceMock = new Mock<ITokenService>();

        // Config padrão para testes
        _configurationMock.Setup(c => c["JWT:RefreshTokenExpirationInMinutes"]).Returns("60");
        _configurationMock.Setup(c => c["JWT:TokenExpirationInMinutes"]).Returns("60");
        _configurationMock.Setup(c => c["JWT:SecretKey"]).Returns("THIS_IS_A_TEST_SECRET_KEY_32_CHARS_MINIMUM!");
        _configurationMock.Setup(c => c["JWT:ValidIssuer"]).Returns("test-issuer");
        _configurationMock.Setup(c => c["JWT:ValidAudience"]).Returns("test-audience");

        _service = new UserService(
            _userManagerMock.Object,
            _roleManagerMock.Object,
            _configurationMock.Object,
            _tokenServiceMock.Object
        );
    }

    #endregion

    #region RegisterAsync

    [Test, Category("Success")]
    public async Task RegisterAsync_ShouldCreateUserAndAssignDefaultRole_WhenCreateSucceeds_AndRoleDoesNotExist()
    {
        // Arrange
        var dto = UserDtoMock.CreateValidRegisterDto();

        _userManagerMock
            .Setup(um => um.CreateAsync(It.IsAny<User>(), dto.Password))
            .ReturnsAsync(IdentityResult.Success);

        _roleManagerMock
            .Setup(rm => rm.RoleExistsAsync("User"))
            .ReturnsAsync(false);

        _roleManagerMock
            .Setup(rm => rm.CreateAsync(It.IsAny<IdentityRole>()))
            .ReturnsAsync(IdentityResult.Success);

        _userManagerMock
            .Setup(um => um.AddToRoleAsync(It.IsAny<User>(), "User"))
            .ReturnsAsync(IdentityResult.Success);

        // Act
        var result = await _service.RegisterAsync(dto);

        // Assert
        Assert.That(result.Succeeded, Is.True);

        _userManagerMock.Verify(
            um => um.CreateAsync(It.Is<User>(u => u.Email == dto.Email && u.UserName == dto.Username), dto.Password),
            Times.Once
        );

        _roleManagerMock.Verify(rm => rm.RoleExistsAsync("User"), Times.Once);
        _roleManagerMock.Verify(rm => rm.CreateAsync(It.Is<IdentityRole>(r => r.Name == "User")), Times.Once);

        _userManagerMock.Verify(
            um => um.AddToRoleAsync(It.Is<User>(u => u.Email == dto.Email), "User"),
            Times.Once
        );
    }

    [Test, Category("Success")]
    public async Task RegisterAsync_ShouldNotCreateRole_WhenRoleAlreadyExists()
    {
        // Arrange
        var dto = UserDtoMock.CreateValidRegisterDto();

        _userManagerMock
            .Setup(um => um.CreateAsync(It.IsAny<User>(), dto.Password))
            .ReturnsAsync(IdentityResult.Success);

        _roleManagerMock
            .Setup(rm => rm.RoleExistsAsync("User"))
            .ReturnsAsync(true);

        _userManagerMock
            .Setup(um => um.AddToRoleAsync(It.IsAny<User>(), "User"))
            .ReturnsAsync(IdentityResult.Success);

        // Act
        var result = await _service.RegisterAsync(dto);

        // Assert
        Assert.That(result.Succeeded, Is.True);

        _roleManagerMock.Verify(rm => rm.RoleExistsAsync("User"), Times.Once);
        _roleManagerMock.Verify(rm => rm.CreateAsync(It.IsAny<IdentityRole>()), Times.Never);

        _userManagerMock.Verify(um => um.AddToRoleAsync(It.IsAny<User>(), "User"), Times.Once);
    }

    [Test, Category("Error")]
    public async Task RegisterAsync_ShouldNotAssignRole_WhenCreateFails()
    {
        // Arrange
        var dto = UserDtoMock.CreateValidRegisterDto();

        var failed = IdentityResult.Failed(new IdentityError { Description = "create failed" });

        _userManagerMock
            .Setup(um => um.CreateAsync(It.IsAny<User>(), dto.Password))
            .ReturnsAsync(failed);

        // Act
        var result = await _service.RegisterAsync(dto);

        // Assert
        Assert.That(result.Succeeded, Is.False);

        _roleManagerMock.Verify(rm => rm.RoleExistsAsync(It.IsAny<string>()), Times.Never);
        _userManagerMock.Verify(um => um.AddToRoleAsync(It.IsAny<User>(), It.IsAny<string>()), Times.Never);
    }

    #endregion

    #region LoginAsync

    [Test, Category("Success")]
    public async Task LoginAsync_ShouldReturnAuthenticationResultTrue_AndUpdateRefreshToken_WhenCredentialsAreValid()
    {
        // Arrange
        var user = UserDataMock.CreateValid();
        user.Email = "user@test.com";
        user.UserName = "user1";

        var dto = UserDtoMock.CreateValidLoginDto();
        dto.Email = user.Email;
        dto.Password = "Valid@123";

        _userManagerMock
            .Setup(um => um.FindByEmailAsync(dto.Email))
            .ReturnsAsync(user);

        _userManagerMock
            .Setup(um => um.CheckPasswordAsync(user, dto.Password))
            .ReturnsAsync(true);

        _userManagerMock
            .Setup(um => um.GetRolesAsync(user))
            .ReturnsAsync(new List<string> { "User" });

        _tokenServiceMock
            .Setup(ts => ts.GenerateRefreshToken())
            .Returns("refresh-token-123");

        // Aqui tanto faz retornar qualquer JwtSecurityToken válido.
        _tokenServiceMock
            .Setup(ts => ts.GenerateAcessToken(It.IsAny<IEnumerable<System.Security.Claims.Claim>>(), It.IsAny<IConfiguration>()))
            .Returns(new System.IdentityModel.Tokens.Jwt.JwtSecurityToken(
                issuer: "test-issuer",
                audience: "test-audience",
                claims: null,
                notBefore: DateTime.UtcNow.AddMinutes(-1),
                expires: DateTime.UtcNow.AddMinutes(60),
                signingCredentials: null
            ));

        _userManagerMock
            .Setup(um => um.UpdateAsync(It.IsAny<User>()))
            .ReturnsAsync(IdentityResult.Success);

        // Act
        var result = await _service.LoginAsync(dto);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result.Success, Is.True);
        Assert.That(result.RefreshToken, Is.EqualTo("refresh-token-123"));
        Assert.That(result.Expiration, Is.Not.EqualTo(DateTime.MinValue));
        Assert.That(result.Token, Is.Not.Null.And.Not.Empty);

        _userManagerMock.Verify(um => um.UpdateAsync(It.Is<User>(u =>
            u.RefreshToken == "refresh-token-123" &&
            u.RefreshTokenExpiryTime > DateTime.UtcNow.AddMinutes(50) // ~60min configurado
        )), Times.Once);

        _tokenServiceMock.Verify(ts => ts.GenerateRefreshToken(), Times.Once);
        _tokenServiceMock.Verify(ts => ts.GenerateAcessToken(It.IsAny<IEnumerable<System.Security.Claims.Claim>>(), _configurationMock.Object), Times.Once);
    }

    [Test, Category("Success")]
    public async Task LoginAsync_ShouldReturnAuthenticationResultFalse_WhenUserDoesNotExist()
    {
        // Arrange
        var dto = UserDtoMock.CreateValidLoginDto();

        _userManagerMock
            .Setup(um => um.FindByEmailAsync(dto.Email))
            .ReturnsAsync((User)null!);

        // Act
        var result = await _service.LoginAsync(dto);

        // Assert
        Assert.That(result.Success, Is.False);
        Assert.That(result.Token, Is.Null);
        Assert.That(result.RefreshToken, Is.Null);
        Assert.That(result.Expiration, Is.EqualTo(DateTime.MinValue));

        _userManagerMock.Verify(um => um.CheckPasswordAsync(It.IsAny<User>(), It.IsAny<string>()), Times.Never);
        _userManagerMock.Verify(um => um.UpdateAsync(It.IsAny<User>()), Times.Never);
    }

    [Test, Category("Success")]
    public async Task LoginAsync_ShouldReturnAuthenticationResultFalse_WhenPasswordIsInvalid()
    {
        // Arrange
        var user = UserDataMock.CreateValid();
        var dto = UserDtoMock.CreateValidLoginDto();
        dto.Email = user.Email!;

        _userManagerMock
            .Setup(um => um.FindByEmailAsync(dto.Email))
            .ReturnsAsync(user);

        _userManagerMock
            .Setup(um => um.CheckPasswordAsync(user, dto.Password))
            .ReturnsAsync(false);

        // Act
        var result = await _service.LoginAsync(dto);

        // Assert
        Assert.That(result.Success, Is.False);
        Assert.That(result.Token, Is.Null);
        Assert.That(result.RefreshToken, Is.Null);
        Assert.That(result.Expiration, Is.EqualTo(DateTime.MinValue));

        _userManagerMock.Verify(um => um.UpdateAsync(It.IsAny<User>()), Times.Never);
        _tokenServiceMock.Verify(ts => ts.GenerateAcessToken(It.IsAny<IEnumerable<System.Security.Claims.Claim>>(), It.IsAny<IConfiguration>()), Times.Never);
        _tokenServiceMock.Verify(ts => ts.GenerateRefreshToken(), Times.Never);
    }

    #endregion

    #region AddRoleAsync

    [Test, Category("Success")]
    public async Task AddRoleAsync_ShouldCreateRole_WhenRoleDoesNotExist()
    {
        // Arrange
        var role = "Admin";

        _roleManagerMock
            .Setup(rm => rm.RoleExistsAsync(role))
            .ReturnsAsync(false);

        _roleManagerMock
            .Setup(rm => rm.CreateAsync(It.IsAny<IdentityRole>()))
            .ReturnsAsync(IdentityResult.Success);

        // Act
        var result = await _service.AddRoleAsync(role);

        // Assert
        Assert.That(result.Succeeded, Is.True);

        _roleManagerMock.Verify(rm => rm.CreateAsync(It.Is<IdentityRole>(r => r.Name == role)), Times.Once);
    }

    [Test, Category("Error")]
    public async Task AddRoleAsync_ShouldFail_WhenRoleAlreadyExists()
    {
        // Arrange
        var role = "User";

        _roleManagerMock
            .Setup(rm => rm.RoleExistsAsync(role))
            .ReturnsAsync(true);

        // Act
        var result = await _service.AddRoleAsync(role);

        // Assert
        Assert.That(result.Succeeded, Is.False);
        Assert.That(result.Errors, Is.Not.Empty);
    }

    #endregion

    #region AssignRoleAsync

    [Test, Category("Success")]
    public async Task AssignRoleAsync_ShouldAssignRole_WhenUserExists()
    {
        // Arrange
        var user = UserDataMock.CreateValid();

        var dto = UserDtoMock.CreateValidUserRoleDto(user.Email!);

        _userManagerMock
            .Setup(um => um.FindByEmailAsync(dto.Email))
            .ReturnsAsync(user);

        _userManagerMock
            .Setup(um => um.AddToRoleAsync(user, dto.Role))
            .ReturnsAsync(IdentityResult.Success);

        // Act
        var result = await _service.AssignRoleAsync(dto);

        // Assert
        Assert.That(result.Succeeded, Is.True);

        _userManagerMock.Verify(um => um.AddToRoleAsync(user, dto.Role), Times.Once);
    }

    [Test, Category("Error")]
    public async Task AssignRoleAsync_ShouldFail_WhenUserIsNotFound()
    {
        // Arrange
        var dto = UserDtoMock.CreateValidUserRoleDto();

        _userManagerMock
            .Setup(um => um.FindByEmailAsync(dto.Email))
            .ReturnsAsync((User)null!);

        // Act
        var result = await _service.AssignRoleAsync(dto);

        // Assert
        Assert.That(result.Succeeded, Is.False);
        Assert.That(result.Errors, Is.Not.Empty);

        _userManagerMock.Verify(um => um.AddToRoleAsync(It.IsAny<User>(), It.IsAny<string>()), Times.Never);
    }

    #endregion
}