package com.cpm;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.datasource.DriverManagerDataSource;

import javax.sql.DataSource;

@Configuration
public class DataConfig {

    @Bean
    public DataSource dataSource() {
        //Note: Use something that supports connection pooling and external configuration in production
        DriverManagerDataSource dataSource = new DriverManagerDataSource();
        dataSource.setDriverClassName("org.postgresql.Driver");
        dataSource.setUrl("jdbc:postgresql://localhost:5432/oauth");
        dataSource.setUsername("oauth_user");
        dataSource.setPassword("P@ssw0rd1");
        return dataSource;
    }
}
