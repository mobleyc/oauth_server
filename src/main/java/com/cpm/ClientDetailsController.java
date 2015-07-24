package com.cpm;


import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.provider.client.JdbcClientDetailsService;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;

import javax.sql.DataSource;

//TODO: Complete
public class ClientDetailsController {

    @Autowired
    @Qualifier("dataSource")
    private DataSource dataSource;

    @RequestMapping("/oauth/clients/{client}/details")
    @ResponseBody
    public ResponseEntity<Void> listTokensForClient(@PathVariable String client) throws Exception {

        return new ResponseEntity<>(HttpStatus.NO_CONTENT);
    }

    //TODO: Move to config class
    public JdbcClientDetailsService clientDetailsService(DataSource dataSource) {
        JdbcClientDetailsService clientDetailsService = new JdbcClientDetailsService(dataSource);
        // This is used to encode secrets as they are added to the database
        clientDetailsService.setPasswordEncoder(new BCryptPasswordEncoder());
        return null;
    }
}
