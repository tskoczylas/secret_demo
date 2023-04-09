package com.prototal.usersecret.security;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototal.usersecret.entity.TokenEntity;
import com.prototal.usersecret.repository.TokenRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;

/**
 * The type Authentication filter is a main Authentication filter
 */
@Log4j2
@RequiredArgsConstructor
public class AuthenticationFilter extends UsernamePasswordAuthenticationFilter {


    private final AuthenticationManager authenticationManager;

    private final TokenRepository tokenRepository;

    private final String tokenAuthKet;

    private final Long tokenExpiryTime;

    private final long MAX_ACTIVE_TOKENS = 2;


    /**
     * Method to define attempt authorization
     * - retrieving password and username from request
     * - creating new PasswordUser Authentication Token
     *
     * @param request  the request
     * @param response the response
     * @return the authentication
     * @throws AuthenticationException the authentication exception
     */
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {

        String adminName = request.getParameter("username");
        String password = request.getParameter("password");

        UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(adminName, password);
        return authenticationManager.authenticate(authenticationToken);
    }

    /**
     * Successful authentication.
     *  - User is being brought from Security Context
     *  - Expiry date being set including off set
     *  - Random Id being set for token
     *  - Generated token id and expiry date being store in DB
     *  - Check in DB that count active token is less than MAX_ACTIVE_TOKENS
     *  - Token is being sent to user
     *
     * @param request        the request
     * @param response       the response
     * @param chain          the chain
     * @param authentication the authentication
     * @throws IOException the io exception
     */
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authentication) throws IOException {
        try {
            User user = (User) authentication.getPrincipal();
            Algorithm algorithm = Algorithm.HMAC256(tokenAuthKet);

            Date expiryDate = new Date(System.currentTimeMillis() + tokenExpiryTime);

            String jwtId = String.valueOf(UUID.randomUUID());


            String accessToken = JWT.create()
                    .withSubject(user.getUsername())
                    .withExpiresAt(expiryDate)
                    .withIssuer(request.getRequestURI())
                    .withJWTId(jwtId)
                    .sign(algorithm);

            tokenRepository.save(TokenEntity.builder().username(user.getUsername()).expiryDate(expiryDate).tokenId(jwtId).build());

            if (tokenRepository.findAllByUsernameAndExpiryDateAfter(user.getUsername(), new Date()).size() > MAX_ACTIVE_TOKENS) {
                response.sendError(400, "You have to many active tokens. Please use existing one before create new one.");
                log.warn("--- User : {} --- is trying to create more that allowed active tokens. ", user.getUsername());
                return;
            }

            Map<String, String> tokens = new HashMap<>();
            tokens.put("access_token", accessToken);

            response.setContentType(APPLICATION_JSON_VALUE);
            new ObjectMapper().writeValue(response.getOutputStream(), tokens);
        } catch (Exception e) {
            log.error("Error inside successfulAuthentication", e);
            response.sendError(301, "Authentication failed");
        }
    }

    /**
     * Unsuccessful authentication.
     *  - log information for audit purpose
     *
     * @param request  the request
     * @param response the response
     * @param failed   the failed
     * @throws IOException      the io exception
     * @throws ServletException the servlet exception
     */
    @Override
    protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response, AuthenticationException failed) throws IOException, ServletException {
        super.unsuccessfulAuthentication(request, response, failed);
        log.warn("Unsuccessful authentication. Login: " + request.getParameter("login") + ", Message:  " + failed.getMessage()
        );
    }
}
