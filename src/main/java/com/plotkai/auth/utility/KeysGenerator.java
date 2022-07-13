package com.plotkai.auth.utility;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.HashMap;
import java.util.Map;

import org.springframework.cache.annotation.Cacheable;
import org.springframework.stereotype.Component;

import lombok.extern.slf4j.Slf4j;

@Component
@Slf4j
public class KeysGenerator {

    Map<String, Object> keys;

    public Map<String, Object> getRSAKeys() {
        if (null == keys) {
            keys = genrateRSAKeys();
            return keys;
        }
        if (keys.size() > 0) {
            return keys;
        } else {
            keys = genrateRSAKeys();
            return keys;
        }
    }

    @Cacheable
    public Map<String, Object> genrateRSAKeys() {
        try {
            log.info("Generating New Keys");
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(AuthConstants.KEYPAIR_GENERATOR_ALGORITHM);
            keyPairGenerator.initialize(2048);
            KeyPair keyPair = keyPairGenerator.generateKeyPair();
            PrivateKey privateKey = keyPair.getPrivate();
            PublicKey publicKey = keyPair.getPublic();
            Map<String, Object> keys = new HashMap<String, Object>();
            keys.put(AuthConstants.PRIVATE_KEY, privateKey);
            keys.put(AuthConstants.PUBLIC_KEY, publicKey);
            log.info("Keys Generated Successfully");
            return keys;
        } catch (Exception e) {
            log.error("Cannot generate RSA keys {}", e);
            return null;
        }
    }

}
