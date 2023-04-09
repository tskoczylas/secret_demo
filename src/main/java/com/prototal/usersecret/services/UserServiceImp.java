package com.prototal.usersecret.services;

import com.prototal.usersecret.entity.SecretEntity;
import com.prototal.usersecret.entity.UserEntity;
import com.prototal.usersecret.models.UserSignInDto;
import com.prototal.usersecret.repository.SecretRepository;
import com.prototal.usersecret.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Collection;
import java.util.Collections;


/**
 * Implementation of User Service, providing a methods perform operation on User in MongoDB
 */
@Service
@RequiredArgsConstructor
public class UserServiceImp implements UserDetailsService, UserService {

    private final UserRepository userRepository;
    private final SecretRepository secretRepository;
    private final EncryptionService encryptionService;

    /**
     * Implementation method from UserDetailsService, use to find user given in Token during authorization to authorize call
     *
     * @param username the username - decrypted from JWT token
     * @return If user existing in DB returning a Instance of User Class Used in Supercity Chains
     * @throws UsernameNotFoundException the username not found exception and fails authorization
     */
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        Collection<SimpleGrantedAuthority> authorities = Collections.
                singleton(new SimpleGrantedAuthority("User"));

        UserEntity userEntity = userRepository.
                findByUsername(username).
                orElseThrow(() -> new UsernameNotFoundException(username));

        return new User(userEntity.getUsername(), userEntity.getPassword(), true, true, true, true, authorities);

    }

    /**
     * Method to save user, when signing in
     *
     * @param userSignInDto the userSignInDto - data provided from POST call
     */
    @Override
    public void signUp(UserSignInDto userSignInDto) {

        String encryptedSecret = encryptionService.encrypt(userSignInDto.getSecret());

        String encodePassword = new BCryptPasswordEncoder().encode(userSignInDto.getPassword());

        userRepository.save(UserEntity.builder().
                username(userSignInDto.getLogin()).
                password(encodePassword).
                firstName(userSignInDto.getFirstName()).
                lastName(userSignInDto.getLastName()).
                email(userSignInDto.getEmail())
                .build());

        secretRepository.save(SecretEntity.builder().
                secret(encryptedSecret).
                username(userSignInDto.getLogin()).
                secretName(userSignInDto.getFirstName() + " " + userSignInDto.getLastName()).build());
    }
}
