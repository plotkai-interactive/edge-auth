package com.plotkai.auth.authentication;

import java.util.HashMap;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import lombok.extern.slf4j.Slf4j;

@RestController
@RequestMapping("/")
@Slf4j
public class AuthController {

    @Autowired
    AuthOperations authOperations;

    @PostMapping("/login")
    public ResponseEntity<String> login(@RequestBody HashMap<String, String> credentials) {
        log.info("Login Controller.. {}", credentials);
        // call some real validation API with credentials
        return new ResponseEntity<>(authOperations.generateToken(), HttpStatus.OK);
    }

    @GetMapping("/.well-known/jwks.json")
    public ResponseEntity<?> jwksEndpoint() {
        log.info("JWKS keyset Controller..");
        HttpHeaders responseHeaders = new HttpHeaders();
        responseHeaders.set("Content-Type", "application/json");
        return new ResponseEntity<>(authOperations.jwksKeySet(), responseHeaders, HttpStatus.OK);
    }

    @PostMapping("/validate")
    public ResponseEntity<Boolean> validate(@RequestBody String token) {
        log.info("Validate token Controller..{}",token);
        return new ResponseEntity<Boolean>(authOperations.validateToken(token), HttpStatus.OK);
    }
}
