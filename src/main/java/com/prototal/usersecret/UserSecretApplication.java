package com.prototal.usersecret;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.data.mongodb.repository.config.EnableMongoRepositories;

@SpringBootApplication
@EnableMongoRepositories

public class UserSecretApplication {

    public static void main(String[] args) {
        SpringApplication.run(UserSecretApplication.class, args);
    }

}
