package com.psychic.octo.spork.restServer.configuration.security.jwt;

import com.psychic.octo.spork.restServer.configuration.security.userdetails.UserDetailsServiceImpl;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
public class JwtAuthTokenFilter extends OncePerRequestFilter {
    @Autowired
    private JwtUtils jwtUtils;

    @Autowired
    private UserDetailsServiceImpl userDetailsService;

    private static final Logger logger = LoggerFactory.getLogger(JwtAuthTokenFilter.class);

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        logger.debug("JwtAuthTokenFilter called for URI: {}", request.getRequestURI());
        try {
            // Get the jwt from the request
            String jwt = parseJwt(request);
            // Validate the jwt
            if (jwt != null && jwtUtils.validateJwtToken(jwt)) {
                // Get the username from the jwt
                String username = jwtUtils.getUserNameFromJwtToken(jwt);
                // Get the user details from the database
                UserDetails userDetails = userDetailsService.loadUserByUsername(username);

                // This method creates the username and password authentication tokens from the user details
                // this will be our authentication object that will be passed and used in the UsernamePasswordAuthenticationFilter.class
                UsernamePasswordAuthenticationToken authentication =
                        new UsernamePasswordAuthenticationToken(userDetails,
                                null,
                                userDetails.getAuthorities());

                logger.debug("Roles from JWT: {}", userDetails.getAuthorities());

                // We need to convert the HttpServletRequest (which is a java class) to a WebAuthenticationDetails (which is a spring class)
                // This is simply a bridge between servlet classes and spring classes
                authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

                SecurityContextHolder.getContext().setAuthentication(authentication);
            }
        } catch (Exception e) {
            logger.error("Cannot set user authentication: {}", e);
        }

        filterChain.doFilter(request, response);
    }

    private String parseJwt(HttpServletRequest request) {
        String jwt = jwtUtils.getJwtFromHeader(request);
        logger.debug("JwtAuthTokenFilter.java: {}", jwt);
        return jwt;
    }
}
