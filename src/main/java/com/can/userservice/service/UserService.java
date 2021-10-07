package com.can.userservice.service;

import com.can.userservice.model.Role;
import com.can.userservice.model.User;
import com.can.userservice.results.DataResult;
import com.can.userservice.results.Result;

import java.util.List;

public interface UserService {

    DataResult<User> save(User user);
    DataResult<Role> saveRole(Role role);
    Result addRoleToUser(String userName, String role);
    DataResult<User> getUser(String userName);
    DataResult<List<User>> getUsers();
    DataResult<List<Role>> getRoles();
}
