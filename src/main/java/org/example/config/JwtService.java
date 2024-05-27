package org.example.config;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Service
public class JwtService {
    @Value("${application.security.jwt.secret-key}")
    private String secretKey;

    @Value("${application.security.jwt.expiration}")
    private long jwtExpiration;

    @Value("${application.security.jwt.refresh-token.expiration}")
    private long refreshTokenExpiration;


    //todo
    // extract the 'username' from the JWT
    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }


    //todo
    // extract a 'one single claim' from the JWT
    public <T> T extractClaim(String token, Function<Claims, T> claimResolver) {
        final Claims claims = extractAllClaims(token);
        return claimResolver.apply(claims);
    }


    //todo
    // generate a JWT with extra claims
    public String generateJWT(Map<String, Object> extraClaims, UserDetails userDetails) {
        return buildToken(extraClaims, userDetails, jwtExpiration);
    }

    //todo
    // generate a 'refresh token' without extra claims
    public String generateRefreshToken(UserDetails userDetails) {
        return buildToken(
                new HashMap<>(), userDetails, refreshTokenExpiration
        );
    }


    //todo
    // build a token
    private String buildToken(
            Map<String, Object> extraClaims,
            UserDetails userDetails,
            long expiration
    ) {
        return Jwts.builder()
                .setClaims(extraClaims)
                .setSubject(userDetails.getUsername())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + expiration))
                .signWith(getSignKey(), SignatureAlgorithm.HS256)
                .compact();
    }


    //todo
    // check the JWT is actually
    // belongs to a user that already in the database and
    // check JWT is not expired
    public boolean isValidToken(String token, UserDetails userDetails) {
        final String username = extractUsername(token);
        return username.equals(userDetails.getUsername()) && !isTokenExpired(token);
    }


    //todo
    // check the JWT is yet expired or not
    private boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }


    //todo
    // extract the 'expiration' from the JWT
    private Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }


    //todo
    // generate a JWT without extra claims
    public String generateJWT(UserDetails userDetails) {
        return generateJWT(new HashMap<>(), userDetails);
    }


    //todo
    // extract 'all the claims' from the JWT
    private Claims extractAllClaims(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(getSignKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }


    //todo
    // decode 'signKey' from the 'secret key'
    private Key getSignKey() {
        byte[] keyBytes = Decoders.BASE64.decode(secretKey);
        return Keys.hmacShaKeyFor(keyBytes);
    }
}
