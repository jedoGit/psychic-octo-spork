package com.psychic.octo.spork.restServer.configuration.security.userdetails;


import com.psychic.octo.spork.restServer.models.User;
import com.psychic.octo.spork.restServer.repositories.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;


@Service
public class UserDetailsServiceImpl implements UserDetailsService {
    @Autowired
    UserRepository userRepository;

    @Override
    @Transactional
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = userRepository.findByUserName(username.toLowerCase())
                .orElseThrow(() -> new UsernameNotFoundException("User Not Found with username: " + username));

        GrantedAuthority authority = new SimpleGrantedAuthority(user.getRole().getRoleName().name());

        return new UserDetailsImpl.Builder()
                .id(user.getUserId())
                .username(user.getUserName())
                .email(user.getEmail())
                .password(user.getPassword())
                .is2faEnabled(user.isTwoFactorEnabled())
                .authorities(List.of(authority))
                .isAccountNonExpired(user.isAccountNonExpired())
                .isAccountNonLocked(user.isAccountNonLocked())
                .isCredentialsNonExpired(user.isCredentialsNonExpired())
                .isEnabled(user.isEnabled())
                .build();
    }
}


