package com.tdi.sso.config;

import javax.sql.DataSource;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.jdbc.DataSourceBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;

@Configuration
public class DatasourceConfiguration {
	@Bean 
	@ConfigurationProperties(prefix = "spring.datasource.hikari")
	DataSource dataSource() {
		return DataSourceBuilder.create().build();
	}

    @Bean
    public JdbcTemplate jdbcTemplate( DataSource dataSource){
        return new JdbcTemplate(dataSource);
    }

    @Bean
    public NamedParameterJdbcTemplate namedJdbcTemplate(  DataSource dataSource){
        return new NamedParameterJdbcTemplate(dataSource);
    }

}
