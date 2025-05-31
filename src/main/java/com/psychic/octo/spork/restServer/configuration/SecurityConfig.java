package com.psychic.octo.spork.restServer.configuration;

import com.psychic.octo.spork.restServer.configuration.security.OAuth2LoginSuccessHandler;
import com.psychic.octo.spork.restServer.models.AppRole;
import com.psychic.octo.spork.restServer.models.Role;
import com.psychic.octo.spork.restServer.models.User;
import com.psychic.octo.spork.restServer.repositories.RoleRepository;
import com.psychic.octo.spork.restServer.repositories.UserRepository;
import com.psychic.octo.spork.restServer.configuration.security.jwt.JwtAuthEntryPoint;
import com.psychic.octo.spork.restServer.configuration.security.jwt.JwtAuthTokenFilter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Lazy;
import org.springframework.core.env.Environment;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;

import java.time.LocalDate;

import static org.springframework.security.config.Customizer.withDefaults;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity(prePostEnabled = true, securedEnabled = true, jsr250Enabled = true) // Remove this if we're not using the @PreAuthorize, @PostAuthorize... etc annotations.
public class SecurityConfig {

    @Value("${frontend.url}")
    private String frontendUrl;

    @Value("${spring.security.admin.name}")
    private String initialAdminUsername;

    @Value("${spring.security.admin.password}")
    private String initialAdminPassword;

    @Value("${spring.security.admin.email}")
    private String initialAdminEmail;

    @Value("${spring.security.user.name}")
    private String initialUsername;

    @Value("${spring.security.user.password}")
    private String initialUserPassword;

    @Value("${spring.security.user.email}")
    private String initialUserEmail;

    @Autowired
    private JwtAuthEntryPoint jwtUnauthorizedHandler;

    @Bean
    public JwtAuthTokenFilter jwtAuthTokenFilter() {
        return new JwtAuthTokenFilter();
    }

    @Autowired
    @Lazy
    OAuth2LoginSuccessHandler oAuth2LoginSuccessHandler;

    @Autowired
    private Environment environment;

    @Bean
    SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        // The order of calls matter here!
        http
//                .cors( cors -> cors
//                        .configurationSource(corsConfigurationSource()))
                .cors(withDefaults())
                .csrf(csrf -> csrf
                        .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
                        .ignoringRequestMatchers("/api/auth/public/**"))
                .authorizeHttpRequests((requests) -> requests
                        .requestMatchers("/api/admin/**").hasRole("ADMIN")       // Enabled PreAuthorize("hasRole('ROLE_ADMIN')") in the AdminController.
                        .requestMatchers("/api/audit/**").hasRole("ADMIN")       // Enabled PreAuthorize("hasRole('ROLE_ADMIN')") in the AuditController.
                        .requestMatchers("/api/auth/public/**").permitAll()
                        .requestMatchers("/api/notes/public/**").permitAll()
                        .requestMatchers("/api/csrf-token").permitAll()
                        .requestMatchers("/oauth2/**").permitAll()
                        .anyRequest().authenticated())
                .oauth2Login( oauth2 -> {
                            oauth2.successHandler(oAuth2LoginSuccessHandler);
                        })
                .exceptionHandling(exception -> exception
                        .authenticationEntryPoint(jwtUnauthorizedHandler))
                .addFilterBefore(jwtAuthTokenFilter(), UsernamePasswordAuthenticationFilter.class)  // Add the JWT Authentication before the UsernamePassword Auth
//                .formLogin(withDefaults())
                .httpBasic(withDefaults());
        return http.build();
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }

// We can use this method for configuring the CORS. Currently, we're configuring CORS through a webconfig
//    @Bean
//    public CorsConfigurationSource corsConfigurationSource() {
//        CorsConfiguration corsConfig = new CorsConfiguration();
//        // Allow specific origins
//        corsConfig.setAllowedOrigins(List.of(frontendUrl));
//        // Allow specific HTTP methods
//        corsConfig.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "OPTIONS"));
//        // Allow specific headers
//        corsConfig.setAllowedHeaders(List.of("*"));
//        // Allow credentials (cookies, authorization headers)
//        corsConfig.setAllowCredentials(true);
//        corsConfig.setMaxAge(3600L);
//        // Define allowed paths (for all paths use "/**")
//        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
//        source.registerCorsConfiguration("/**", corsConfig); // Apply to all endpoints
//
//        return source;
//    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    // These are initial users created. Once the application is created, both user password need to be updated!
    @Bean
    public CommandLineRunner initData(RoleRepository roleRepository, UserRepository userRepository, PasswordEncoder passwordEncoder) {
        return args -> {
            // Create Initial Roles Here!
            Role userRole = roleRepository.findByRoleName(AppRole.ROLE_USER)
                    .orElseGet(() -> roleRepository.save(new Role(AppRole.ROLE_USER)));
            Role adminRole = roleRepository.findByRoleName(AppRole.ROLE_ADMIN)
                    .orElseGet(() -> roleRepository.save(new Role(AppRole.ROLE_ADMIN)));

            // This initial user account will not be used! It will be set to expired!
            if (!userRepository.existsByUserName(initialUsername)) {

                // Create new user account
                User user1 = new User.Builder()
                        .userName(initialUsername)
                        .email(initialUserEmail)
                        .password(passwordEncoder.encode(initialUserPassword))
                        .role(userRole)
                        .isAccountNonLocked(false)
                        .isAccountNonExpired(false)
                        .isCredentialsNonExpired(false)
                        .isEnabled(false)
                        .credentialsExpiryDate(LocalDate.now().minusYears(1))
                        .accountExpiryDate(LocalDate.now().minusYears(1))
                        .is2faEnabled(false)
                        .signUpMethod("security-config")
                        .build();

                userRepository.save(user1);
            }

            if (!userRepository.existsByUserName(initialAdminUsername.toLowerCase())) {

                // Create new user account
                User admin = new User.Builder()
                        .userName(initialAdminUsername)
                        .email(initialAdminEmail)
                        .password(passwordEncoder.encode(initialAdminPassword))
                        .role(adminRole)
                        .isAccountNonLocked(true)
                        .isAccountNonExpired(true)
                        .isCredentialsNonExpired(true)
                        .isEnabled(true)
                        .credentialsExpiryDate(LocalDate.now().plusYears(1))
                        .accountExpiryDate(LocalDate.now().plusYears(1))
                        .is2faEnabled(false)
                        .signUpMethod("security-config")
                        .build();

                userRepository.save(admin);
            }
        };
    }

}
