package com.prototal.usersecret.security;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.prototal.usersecret.repository.TokenRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;


import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

import static org.springframework.http.HttpHeaders.AUTHORIZATION;

/**
 * The type Authorization filter is main component that Authorize users.
 */
@Log4j2
@RequiredArgsConstructor
public class AuthorizationFilter extends OncePerRequestFilter {



    private final String tokenEncKey;
    private final TokenRepository tokenRepository;


    /**
     * If valid Barer token is provided method will:
     *  - decrypt Token,
     *  -  check if token id is in database
     *  - if that is true will authorize user and will save token information to SecurityContext
     *
     * @param request     the request
     * @param response    the response
     * @param filterChain the filter chain
     * @throws IOException      the io exception
     * @throws ServletException the servlet exception
     */
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws IOException, ServletException {

        if (request.getServletPath().equals("/api/v1/sign-in")) {
            filterChain.doFilter(request, response);
            return;
        }

        String authorizationHeader = request.getHeader(AUTHORIZATION);

        if (authorizationHeader == null || !authorizationHeader.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            return;
        }

        try {
            String token = authorizationHeader.replace("Bearer ", "");
            Algorithm algorithm = Algorithm.HMAC256(tokenEncKey);
            JWTVerifier verifier = JWT.require(algorithm).build();
            DecodedJWT decodedJWT = verifier.verify(token);

            String username = decodedJWT.getSubject();

            UsernamePasswordAuthenticationToken authenticationToken =
                    new UsernamePasswordAuthenticationToken(username, decodedJWT.getId(), null);

            if (!tokenRepository.findByTokenId(decodedJWT.getId()).isPresent()) {
                throw new IllegalAccessException("Try to authorize Token that is not in DB");
            }

            SecurityContextHolder.getContext().setAuthentication(authenticationToken);

            filterChain.doFilter(request, response);
        } catch (Exception e) {
            log.error("Error during authorization.", e);
            response.sendError(401, "Authorization failed");
        }
    }

}
