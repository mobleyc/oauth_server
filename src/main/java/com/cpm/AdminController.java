package com.cpm;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.ConsumerTokenServices;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;

import java.security.Principal;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

/*
 * Copied from https://github.com/spring-projects/spring-security-oauth/blob/master/samples/oauth2/sparklr/src/main/java/org/springframework/security/oauth/examples/sparklr/mvc/AdminController.java
 */
@Controller
public class AdminController {

    private TokenStore tokenStore;

    private ConsumerTokenServices tokenServices;

    /*
     * View a list of tokens granted to a client
     */
    @RequestMapping("/oauth/clients/{client}/tokens")
    @ResponseBody
    public Collection<OAuth2AccessToken> listTokensForClient(@PathVariable String client) throws Exception {
        return enhance(tokenStore.findTokensByClientId(client));
    }

    /*
     * Revoke an access token granted to a user. If the token has a refresh token, it will also be revoked.
     */
    @RequestMapping(value = "/oauth/users/{user}/tokens/{token}", method = RequestMethod.DELETE)
    public ResponseEntity<Void> revokeToken(@PathVariable String user, @PathVariable String token, Principal principal)
            throws Exception {
        checkResourceOwner(user, principal);
        if (tokenServices.revokeToken(token)) {
            return new ResponseEntity<>(HttpStatus.NO_CONTENT);
        } else {
            return new ResponseEntity<>(HttpStatus.NOT_FOUND);
        }
    }

    private void checkResourceOwner(String user, Principal principal) {
        if (principal instanceof OAuth2Authentication) {
            OAuth2Authentication authentication = (OAuth2Authentication) principal;
            // TODO: Allow for an admin to view?
            if (!authentication.isClientOnly() && !user.equals(principal.getName())) {
                throw new AccessDeniedException(String.format("User '%s' cannot obtain tokens for user '%s'",
                        principal.getName(), user));
            }
        }
    }

    private Collection<OAuth2AccessToken> enhance(Collection<OAuth2AccessToken> tokens) {
        Collection<OAuth2AccessToken> result = new ArrayList<>();
        for (OAuth2AccessToken prototype : tokens) {
            DefaultOAuth2AccessToken token = new DefaultOAuth2AccessToken(prototype);
            OAuth2Authentication authentication = tokenStore.readAuthentication(token);
            if (authentication == null) {
                continue;
            }
            String clientId = authentication.getOAuth2Request().getClientId();
            if (clientId != null) {
                Map<String, Object> map = new HashMap<>(token.getAdditionalInformation());
                map.put("client_id", clientId);
                token.setAdditionalInformation(map);
                result.add(token);
            }
        }
        return result;
    }

    public void setTokenServices(ConsumerTokenServices tokenServices) {
        this.tokenServices = tokenServices;
    }

    public void setTokenStore(TokenStore tokenStore) {
        this.tokenStore = tokenStore;
    }
}
