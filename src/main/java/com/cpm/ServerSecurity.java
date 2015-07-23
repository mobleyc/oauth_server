package com.cpm;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.oauth2.provider.token.ConsumerTokenServices;
import org.springframework.security.oauth2.provider.token.TokenStore;

//
// ref: https://github.com/spring-projects/spring-security-oauth/blob/master/samples/oauth2/sparklr/src/main/java/org/springframework/security/oauth/examples/sparklr/config/SecurityConfiguration.java
@Configuration
@EnableWebSecurity
public class ServerSecurity extends WebSecurityConfigurerAdapter {

    @Autowired
    private CustomAuthenticationProvider customAuthenticationProvider;

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.authenticationProvider(customAuthenticationProvider);
    }

    /*
     * This exists to add security to the endpoints exposed by the OAuth Server (e.g. /token). See
     * the usage of AuthenticationManager in OauthServer.java.
     */
    @Override
    @Bean
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }

    @Bean
    public AdminController adminController(TokenStore tokenStore,
                                           @Qualifier("consumerTokenServices") ConsumerTokenServices tokenServices) {
        AdminController adminController = new AdminController();
        adminController.setTokenStore(tokenStore);
        adminController.setTokenServices(tokenServices);
        return adminController;
    }
}
