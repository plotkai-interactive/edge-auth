package com.plotkai.auth.utility;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import lombok.extern.slf4j.Slf4j;

@RestController
@RequestMapping("/")
@Slf4j
public class HealthCheckController {

    @GetMapping("/health")
    public ResponseEntity<Boolean> health() {
        log.info("Health check Controller..");
        return new ResponseEntity<Boolean>(true, HttpStatus.OK);
    }

}
