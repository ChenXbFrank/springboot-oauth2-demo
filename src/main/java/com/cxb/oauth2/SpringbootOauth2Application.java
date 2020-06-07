package com.cxb.oauth2;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cache.annotation.EnableCaching;

@SpringBootApplication
@EnableCaching
public class SpringbootOauth2Application {

    public static void main(String[] args) {
        SpringApplication.run(SpringbootOauth2Application.class, args);
    }

}
