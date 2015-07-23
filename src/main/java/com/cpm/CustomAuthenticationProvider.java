package com.cpm;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;

import static java.util.Collections.singleton;

// A custom AuthenticationProvider can be used to integrate with an existing credential store.
@Component
public class CustomAuthenticationProvider implements AuthenticationProvider {

    // All authenticated users will be a member of this authority.
    private String ROLE_USER = "ROLE_USER";

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        String name = authentication.getName();
        String password = authentication.getCredentials().toString();

        if ((null != name) && name.equalsIgnoreCase("test")) {
            // Let's use exceptions for control flow, ugh....
            //
            // Note:
            //   The error message for this exception is also returned in the OAuth error response,
            //   returned to the HTTP client.
            //
            //   Exceptions to throw on errors:
            //     1. BadCredentialsException
            //     2. AccountStatusException - Expired, locked or disabled accounts
            //
            //   ref: https://github.com/spring-projects/spring-security-oauth/blob/master/spring-security-oauth2/src/main/java/org/springframework/security/oauth2/provider/password/ResourceOwnerPasswordTokenGranter.java
            //
            throw new BadCredentialsException("omg omg omg");
        }

        return new UsernamePasswordAuthenticationToken(name, password, singleton(new SimpleGrantedAuthority(ROLE_USER)));
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return authentication.equals(UsernamePasswordAuthenticationToken.class);
    }
}
