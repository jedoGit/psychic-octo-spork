package com.psychic.octo.spork.restServer.configuration.security;

import com.psychic.octo.spork.restServer.configuration.security.jwt.JwtUtils;
import com.psychic.octo.spork.restServer.configuration.security.userdetails.UserDetailsImpl;
import com.psychic.octo.spork.restServer.models.AppRole;
import com.psychic.octo.spork.restServer.models.Role;
import com.psychic.octo.spork.restServer.models.User;
import com.psychic.octo.spork.restServer.repositories.RoleRepository;
import com.psychic.octo.spork.restServer.services.UserService;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.IOException;
import java.time.LocalDate;
import java.util.*;
import java.util.stream.Collectors;

@Component
@RequiredArgsConstructor
public class OAuth2LoginSuccessHandler extends SavedRequestAwareAuthenticationSuccessHandler {

    @Autowired
    private final UserService userService;

    @Autowired
    private final JwtUtils jwtUtils;

    @Autowired
    RoleRepository roleRepository;

    @Value("${frontend.url}")
    private String frontendUrl;

    private String username;
    private String email;
    private String idAttributeKey;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws ServletException, IOException {

        // First, we'll need the authentication object to get the authentication token
        OAuth2AuthenticationToken oAuth2AuthenticationToken = (OAuth2AuthenticationToken) authentication;

        // Check if the client registration id
        if ("github".equals(oAuth2AuthenticationToken.getAuthorizedClientRegistrationId()) ||
                "google".equals(oAuth2AuthenticationToken.getAuthorizedClientRegistrationId())) {

            // Get the authenticated user. This will come from the authentication principal
            DefaultOAuth2User principal = (DefaultOAuth2User) authentication.getPrincipal();

            // Get all of the attributes of the authenticated user.
            Map<String, Object> attributes = principal.getAttributes();

            // We only want to grab the email and name attributes from the authenticated user
            email = attributes.getOrDefault("email", "").toString();
            String name = attributes.getOrDefault("name", "").toString();

            // Each OAuth2 provider will pass data differently, so we'll handle getting the username information based
            // on OAuth2 provider.
            if ("github".equals(oAuth2AuthenticationToken.getAuthorizedClientRegistrationId())) {
                username = attributes.getOrDefault("login", "").toString();
                idAttributeKey = "id";
            } else if ("google".equals(oAuth2AuthenticationToken.getAuthorizedClientRegistrationId())) {
                username = email.split("@")[0];
                idAttributeKey = "sub";
            } else {
                username = "";
                idAttributeKey = "id";
            }

            // convert Username to lowercase
            username = username.toLowerCase();
            // convert email to lowercase
            email = email.toLowerCase();

            // Let's print out the email, name and username
            System.out.println("HELLO OAUTH: " + oAuth2AuthenticationToken.getAuthorizedClientRegistrationId() + " : " +
                     email + " : " + name + " : " + username);

            // We'll use the email to find if it there is a user with this email that already exists in our users repository
            userService.findByEmail(email)
                    .ifPresentOrElse(user -> {
                        // We'll get all the roles of this particular user and create an Oauth2User object with id attrib key
                        DefaultOAuth2User oauthUser = new DefaultOAuth2User(
                                List.of(new SimpleGrantedAuthority(user.getRole().getRoleName().name())),
                                attributes,
                                idAttributeKey
                        );
                        // We'll create an authentication object from the Oauth2 auth token
                        Authentication securityAuth = new OAuth2AuthenticationToken(
                                oauthUser,
                                List.of(new SimpleGrantedAuthority(user.getRole().getRoleName().name())),
                                oAuth2AuthenticationToken.getAuthorizedClientRegistrationId()
                        );
                        // Don't forget to set the authentication context
                        SecurityContextHolder.getContext().setAuthentication(securityAuth);
                    }, () -> {
                        // Create a user role object.. don't assign an admin!
                        Role userRole = roleRepository.findByRoleName(AppRole.ROLE_USER)
                                .orElseThrow( () -> new RuntimeException("Default role not found")); // Fetch existing role

                        // Set the rest of the user attibutes
                        // Username and email will be saved lowercase in database

                        // Create new user account
                        User newUser = new User.Builder()
                                .userName(username)
                                .email(email)
                                .role(userRole)
                                .isAccountNonLocked(true)
                                .isAccountNonExpired(true)
                                .isCredentialsNonExpired(true)
                                .isEnabled(true)
                                .credentialsExpiryDate(LocalDate.now().plusYears(1))
                                .accountExpiryDate(LocalDate.now().plusYears(1))
                                .is2faEnabled(false)
                                .signUpMethod("oauth2-" + oAuth2AuthenticationToken.getAuthorizedClientRegistrationId())
                                .build();

                        // Save the new user object to the user repository
                        // This means we're auto provisioning the new Oauth2 user if it's not in our user repository
                        userService.registerUser(newUser);

                        // Setup the authentication object so we can set the security context
                        DefaultOAuth2User oauthUser = new DefaultOAuth2User(
                                List.of(new SimpleGrantedAuthority(newUser.getRole().getRoleName().name())),
                                attributes,
                                idAttributeKey
                        );

                        Authentication securityAuth = new OAuth2AuthenticationToken(
                                oauthUser,
                                List.of(new SimpleGrantedAuthority(newUser.getRole().getRoleName().name())),
                                oAuth2AuthenticationToken.getAuthorizedClientRegistrationId()
                        );
                        // Don't forget to set the security context
                        SecurityContextHolder.getContext().setAuthentication(securityAuth);
                    });
        }

        this.setAlwaysUseDefaultTargetUrl(true);

        // JWT TOKEN LOGIC
        DefaultOAuth2User oauth2User = (DefaultOAuth2User) authentication.getPrincipal();
        Map<String, Object> attributes = oauth2User.getAttributes();

        // Extract necessary attributes
//        String email = (String) attributes.get("email");
        System.out.println("OAuth2LoginSuccessHandler: " + username + " : " + email);

        // We need to add the user role from our database
        Set<SimpleGrantedAuthority> authorities = oauth2User.getAuthorities().stream()
                .map(authority -> new SimpleGrantedAuthority(authority.getAuthority())).collect(Collectors.toSet());

        // email is already converted to lowercase here
        User user = userService.findByEmail(email)
                .orElseThrow(() -> new RuntimeException("User Not Found"));

        // Add the user role to authorities
        authorities.add(new SimpleGrantedAuthority(user.getRole().getRoleName().name()));

        // Create UserDetailsImpl instance
        UserDetailsImpl userDetails = new UserDetailsImpl.Builder()
                .id(user.getUserId())
                .username(user.getUserName())
                .email(user.getEmail())
                .password(null) // we don't return the password to the frontend!!!!
                .is2faEnabled(user.isTwoFactorEnabled())
                .authorities(authorities)
                .isAccountNonExpired(user.isAccountNonExpired())
                .isAccountNonLocked(user.isAccountNonLocked())
                .isCredentialsNonExpired(user.isCredentialsNonExpired())
                .isEnabled(user.isEnabled())
                .build();

        // Generate JWT token
        String jwtToken = jwtUtils.generateTokenFromUsername(userDetails);

        // Redirect to the frontend with the JWT token
        String targetUrl = UriComponentsBuilder.fromUriString(frontendUrl + "/oauth2/redirect")
                .queryParam("token", jwtToken)
                .build().toUriString();
        this.setDefaultTargetUrl(targetUrl);
        super.onAuthenticationSuccess(request, response, authentication);
    }
}