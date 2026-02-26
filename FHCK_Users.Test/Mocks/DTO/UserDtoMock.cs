using Bogus;
using FHCK_Users.Application.DTO;

namespace FHCK_Users.Test.Mocks.DTO;

public static class UserDtoMock
{
    public static RegisterDTO CreateValidRegisterDto()
    {
        var faker = new Faker("pt_BR");

        return new RegisterDTO
        {
            Email = faker.Internet.Email(),
            Username = faker.Internet.UserName(),
            Password = faker.Internet.Password(length: 10, memorable: false)
        };
    }

    public static LoginDTO CreateValidLoginDto()
    {
        var faker = new Faker("pt_BR");

        return new LoginDTO
        {
            Email = faker.Internet.Email(),
            Password = faker.Internet.Password(length: 10, memorable: false)
        };
    }

    public static UserRoleDTO CreateValidUserRoleDto()
    {
        var faker = new Faker("pt_BR");

        return new UserRoleDTO
        {
            Email = faker.Internet.Email(),
            Role = faker.PickRandom(new[] { "Admin", "User", "Manager" })
        };
    }

    public static UserRoleDTO CreateValidUserRoleDto(string email)
    {
        var faker = new Faker("pt_BR");

        return new UserRoleDTO
        {
            Email = email,
            Role = faker.PickRandom(new[] { "Admin", "User", "Manager" })
        };
    }
}
