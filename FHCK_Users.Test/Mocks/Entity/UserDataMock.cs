using Bogus;
using FHCK_Users.Domain.Entity;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace FHCK_Users.Test.Mocks.Entity
{
    public static class UserDataMock
    {
        public static User CreateValid()
        {
            var faker = new Faker("pt_BR");

            return new User
            {
                Id =  Guid.NewGuid().ToString(),
                Email = faker.Internet.Email(),
                UserName = faker.Internet.UserName(),
                PasswordHash = faker.Internet.Password(),
                PhoneNumber = faker.Phone.PhoneNumber(),
                
            };
        }
    }

    
}
