﻿using ApiPersons.Utilities;
using PantAPIDreamsStyle.models.user;

namespace ApiPersons.Repositories
{
    public interface IUserRepository
    {
        Task<IEnumerable<User>> getListUsers();
        Task<User> getUser(string documentNumber);
        Task<User> getUserEmail(string email);
        Task<bool> addUser(User user);
        Task<bool> removeUser(User user);
        Task<bool> updateUser(UpdateDataUserModel updateDataUserModel);
        Task<User> login(string email, string password);
        Task<User> getUserRecoveryAccount(string email);
        Task<User> UpdateNewPassword(string email, string token, string newPassword);
        Task<User> setToken(string email, string token);
    }
}
