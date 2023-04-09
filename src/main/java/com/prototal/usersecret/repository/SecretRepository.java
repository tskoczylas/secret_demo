package com.prototal.usersecret.repository;

import com.prototal.usersecret.entity.SecretEntity;
import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface SecretRepository extends MongoRepository<SecretEntity,Long> {

    Optional<SecretEntity> findByUsername(String username);
}
