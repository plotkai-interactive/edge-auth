package com.plotkai.auth.authentication;

import java.net.URL;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.stereotype.Component;

import com.auth0.jwk.GuavaCachedJwkProvider;
import com.auth0.jwk.Jwk;
import com.auth0.jwk.JwkProvider;
import com.auth0.jwk.UrlJwkProvider;
import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.SignatureVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.plotkai.auth.utility.AuthConstants;
import com.plotkai.auth.utility.KeysGenerator;

import io.jsonwebtoken.Jwts;
import lombok.extern.slf4j.Slf4j;
import net.minidev.json.JSONObject;

@Component
@Slf4j
public class AuthOperations {

    @Autowired
    KeysGenerator keys;

    @Value("${server.port}")
    private String serverPort;

    UUID kid = UUID.randomUUID();

    public String generateToken() {
        String token = null;
        try {
            PrivateKey privateKey = (PrivateKey) keys.getRSAKeys().get(AuthConstants.PRIVATE_KEY);

            Date today = new Date();
            Calendar c = Calendar.getInstance();
            c.setTime(today);
            c.add(Calendar.DATE, 1);
            Date tomorrow = c.getTime();

            token = Jwts.builder()
            .setHeaderParam("kid", kid)
            .setId(UUID.randomUUID().toString())
            .setIssuedAt(today)
            .setSubject("tester")
            .setIssuer("localhost")
            .setExpiration(tomorrow)
            .signWith(privateKey)
            .compact();

            log.info("Token generated");
        } catch (Exception e) {
            log.error("Cannot generate token", e.getMessage());
        }
        return token;
    }

    @Cacheable
    public Map<String, List<JSONObject>> jwksKeySet() {
        try {
            PublicKey publicKey = (PublicKey) keys.getRSAKeys().get(AuthConstants.PUBLIC_KEY);

            JWK jwk = new RSAKey.Builder((RSAPublicKey) publicKey)
                    .keyUse(KeyUse.SIGNATURE)
                    .keyID(kid.toString())
                    .build();

            System.out.println(jwk.toJSONString());
            System.out.println(jwk.toJSONObject());
            System.out.println(jwk.toString());

            Map<String, List<JSONObject>> keyset = new HashMap<String, List<JSONObject>>();
            List<JSONObject> keys = new ArrayList<JSONObject>();

            keys.add(jwk.toJSONObject());
            keyset.put("keys", keys);

            return keyset;
        } catch (Exception e) {
            log.error("Cannot generate JWKS keyset", e.getMessage());
        }
        return null;
    }

    public Boolean validateToken(String token) {
        log.info("Verifying token via JWKS");
        try {
            DecodedJWT jwt = JWT.decode(token);
            JwkProvider http = new UrlJwkProvider(new URL("http://localhost:".concat(serverPort).concat("/.well-known/jwks.json")));
            JwkProvider provider = new GuavaCachedJwkProvider(http);
            Jwk jwk = provider.get(jwt.getKeyId());
            Algorithm algorithm = Algorithm.RSA256((RSAPublicKey) jwk.getPublicKey(), null);
            algorithm.verify(jwt);

            if (jwt.getExpiresAt().before(Calendar.getInstance().getTime())) {
                log.error("Expired token.");
                return false;
            }
            log.info("Token Verified");
            return true;
        } catch(SignatureVerificationException s){
            log.error("JWT verification failed : {}", s.getMessage());
            return false;
        } catch (Exception e) {
            log.error("Error occured while verifying token : {}", e.getMessage());
            return false;
        }
    }

}
