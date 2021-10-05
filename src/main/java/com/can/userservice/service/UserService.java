package com.can.userservice.service;

import com.can.userservice.model.Role;
import com.can.userservice.model.User;

import java.util.List;

public interface UserService {

    User save(User user);
    Role saveRole(Role role);
    void addRoleToUser(String userName,String role);
    User getUser(String userName);
    List<User> getUsers();
}
