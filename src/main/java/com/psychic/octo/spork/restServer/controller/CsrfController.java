package com.psychic.octo.spork.restServer.controller;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class CsrfController {

    // This only returns the csrf token from the client which was received from the HTTP request.
    // We'll pass this back to client specifically to be used in POSTMan so we can perform some
    // submission with csrf security enabled in the backend.
    @GetMapping("/api/v1/csrf-token")
    public CsrfToken csrfToken(HttpServletRequest request) {
        return (CsrfToken) request.getAttribute(CsrfToken.class.getName());
    }
}

