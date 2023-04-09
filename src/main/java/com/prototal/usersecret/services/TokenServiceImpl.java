package com.prototal.usersecret.services;

import com.prototal.usersecret.entity.UserEntity;
import com.prototal.usersecret.repository.TokenRepository;
import com.prototal.usersecret.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Date;

/**
 * Service taking park in Token Management for Authorization and Authentication
 */
@Service
@RequiredArgsConstructor
public class TokenServiceImpl implements TokenService {

    private final TokenRepository tokenRepository;
    private final UserRepository userRepository;

    /**
     * When Authorized user sending log out request, token Id is being brought from Security Context
     * and current token information is being removed from database.
     */
    @Override
    public void logOut() {
        String tokenId = (String) SecurityContextHolder.getContext().getAuthentication().getCredentials();
        tokenRepository.deleteByTokenId(tokenId);
    }

    /**
     When Authorized user sending reset password request, user name being brought from Security Context and:
     * - all active tokens for users are being deleted
     * - password being change and entity saved
     * @param newPassword the new password
     */
    @Override
    public void resetPassword(String newPassword) {
        String user = (String) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        tokenRepository.deleteAllByUsernameAndExpiryDateAfter(user, new Date());

        UserEntity userEntity = userRepository.findByUsername(user).orElseThrow(() -> new UsernameNotFoundException("Trying to change password to user that not exist in db"));
        userEntity.setPassword(new BCryptPasswordEncoder().encode(newPassword));
        userRepository.save(userEntity);
    }
}
