package com.cpm;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JdbcTokenStore;
import org.springframework.transaction.annotation.EnableTransactionManagement;
import org.springframework.web.bind.annotation.RestController;

import javax.sql.DataSource;

/*
 * Run
 *     mvn package && java -jar target/oauth_server-1.0-SNAPSHOT.jar OR
 *     mvn package spring-boot:run
 *
 * List of endpoints exposed by Spring Security OAuth 2
 *   https://github.com/spring-projects/spring-security-oauth/tree/master/spring-security-oauth2/src/main/java/org/springframework/security/oauth2/provider/endpoint
 *
 * Other Notes:
 *   Security for Microservices with Spring - http://presos.dsyer.com/decks/microservice-security.html
 *   Generating a client secret - http://stackoverflow.com/questions/23652166/how-to-generate-oauth-2-client-id-and-secret
 */
@Configuration
@ComponentScan
@EnableAutoConfiguration
@RestController
@EnableTransactionManagement
public class OauthServer {

    public static void main(String[] args) throws Exception {
        SpringApplication.run(OauthServer.class, args);
    }

    @Configuration
    @EnableAuthorizationServer
    protected static class OAuth2Config extends AuthorizationServerConfigurerAdapter {

        @Autowired
        @Qualifier("authenticationManagerBean")
        private AuthenticationManager authenticationManager;


        @Autowired
        @Qualifier("dataSource")
        private DataSource dataSource;

        /*
         * Examples:
         *
         * client_credentials
         *   -- Works -> HTTP 200
         *   curl -u my-client-with-secret:secret -i http://localhost:8080/oauth/token -d 'grant_type=client_credentials'
         *
         * password
         *   -- Test for invalid credentials
         *   curl -u my-client-with-secret:secret -i http://localhost:8080/oauth/token -d 'grant_type=password' -d 'username=test' -d 'password=test'
         *
         *   -- Works -> HTTP 200
         *   curl -u my-client-with-secret:secret -i http://localhost:8080/oauth/token -d 'grant_type=password' -d 'username=marissa' -d 'password=koala'
         *
         * check_token
         *   -- Fails -> HTTP 403 Access denied
         *   curl -u my-client-with-secret:secret -i http://localhost:8080/oauth/check_token?token=123
         *
         *   curl -u resource-server:secret -i http://localhost:8080/oauth/check_token?token=328fcf23-ac0a-4a56-a9f9-e3c3fcabf823
         *   //TODO: Cache successful token lookups for some amount of time, e.g. 10 minutes
         */
        @Override
        public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
            clients.jdbc(dataSource)
                    .withClient("my-client-with-secret")
                    .secret("secret")
                    /*
                     * Can be any of:
                     *   "password"
                     *   "authorization_code"
                     *   "refresh_token"
                     *   "implicit"
                     *   "client_credentials"
                     */
                    //Note: The OAuth spec does not allow refresh tokens for client_credentials grant types.
                    .authorizedGrantTypes("client_credentials", "password", "refresh_token")
                    .scopes("default")
                    .authorities("ROLE_CLIENT")
                    // Default 12 hours
                    // ref: https://github.com/spring-projects/spring-security-oauth/blob/master/spring-security-oauth2/src/main/java/org/springframework/security/oauth2/provider/token/DefaultTokenServices.java
                    // How long should an access token live? http://stackoverflow.com/questions/7030694/oauth2-why-do-access-tokens-expire
                    .accessTokenValiditySeconds(3600)
                    // Default 30 days
                    .refreshTokenValiditySeconds(60 * 60 * 24 * 30)
                    .and()
                    // Resource server needs access to /check_token endpoint. Other clients do not.
                    .withClient("resource-server")
                    .secret("secret")
                    .authorities("ROLE_TRUSTED_CLIENT");
        }

        // For memory store use InMemoryTokenStore
        public TokenStore tokenStore() {
            return new JdbcTokenStore(dataSource);
        }

        @Override
        public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
            endpoints.tokenStore(tokenStore()).authenticationManager(authenticationManager);
        }

        @Override
        public void configure(AuthorizationServerSecurityConfigurer oauthServer) throws Exception {
            oauthServer.realm("example")
                    .checkTokenAccess("hasAuthority('ROLE_TRUSTED_CLIENT')");
        }
    }
}