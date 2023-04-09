package com.prototal.usersecret.repository;

import com.prototal.usersecret.entity.UserEntity;
import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserRepository extends MongoRepository<UserEntity,Long> {

    Optional<UserEntity> findByUsername(String username);
}
