package com.psychic.octo.spork.restServer.repositories;


import com.psychic.octo.spork.restServer.models.AppRole;
import com.psychic.octo.spork.restServer.models.Role;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface RoleRepository extends JpaRepository<Role, Long> {
    Optional<Role> findByRoleName(AppRole appRole);

}

