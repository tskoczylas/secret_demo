package com.prototal.usersecret.repository;

import com.prototal.usersecret.entity.TokenEntity;
import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.stereotype.Repository;

import java.util.Date;
import java.util.List;
import java.util.Optional;

@Repository
public interface TokenRepository extends MongoRepository<TokenEntity,String> {

    List<TokenEntity> findAllByUsernameAndExpiryDateAfter(String username, Date now);
    void deleteAllByUsernameAndExpiryDateAfter(String username, Date now);

    Optional<TokenEntity> findByTokenId(String tokenId);
    void deleteByTokenId(String tokenId);
}
