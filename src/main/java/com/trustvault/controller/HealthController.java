package com.trustvault.controller;

import com.trustvault.dto.HealthResponseDto;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Controller exposing the application health probe.
 *
 * Responsibilities:
 * - Handle HTTP GET requests to /api/health.
 * - Return lightweight status indicating the service is running.
 * - Publicly accessible without authentication (configured in SecurityConfig).
 */
@RestController
@RequestMapping("/api/health")
public class HealthController {

    @GetMapping
    public ResponseEntity<HealthResponseDto> checkHealth() {
        return ResponseEntity.ok(HealthResponseDto.up());
    }
}
