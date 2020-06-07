package com.cxb.oauth2.config;

import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configurers.ResourceServerSecurityConfigurer;

/**
 *  资源服务器
 */
@Slf4j
@Configuration
@EnableResourceServer
public class ResourceServerConfig extends ResourceServerConfigurerAdapter {
    private static final String RESOURCE_ID = "oauth-resource";

    @Override
    public void configure(ResourceServerSecurityConfigurer resources) {
        resources.resourceId(RESOURCE_ID).stateless(true);
    }

//    http://localhost:8080/oauth/authorize?response_type=code&client_id=client_id_1&redirect_uri=http://example.com
    @Override
    public void configure(HttpSecurity http) throws Exception {
        http.logout().deleteCookies("JSESSIONID");
        http.csrf().disable();
        http.formLogin().disable();
        http.sessionManagement().disable();
        http.cors();
        http.requestMatchers().antMatchers("/user/**")
                .and()
                .authorizeRequests().anyRequest().authenticated();

    }



}