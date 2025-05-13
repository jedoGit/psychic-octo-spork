package com.psychic.octo.spork.restServer.services;

import com.psychic.octo.spork.restServer.models.User;
import com.psychic.octo.spork.restServer.dto.UserDTO;

import java.util.List;

public interface UserService {
    void updateUserRole(Long userId, String roleName);

    List<User> getAllUsers();

    UserDTO getUserById(Long id);

    User findByUsername(String username);
}
