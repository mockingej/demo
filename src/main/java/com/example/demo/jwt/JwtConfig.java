package com.example.demo.jwt;

import com.google.common.net.HttpHeaders;
import io.jsonwebtoken.security.Keys;
import org.springframework.boot.context.properties.ConfigurationProperties;

import javax.crypto.SecretKey;

@ConfigurationProperties(prefix = "application.jwt")
public class JwtConfig {

    private String key;
    private String prefix;
    private Integer expiration;

    public JwtConfig() {
    }

    public String getKey() {
        return key;
    }

    public void setKey(String key) {
        this.key = key;
    }

    public String getPrefix() {
        return prefix;
    }

    public void setPrefix(String prefix) {
        this.prefix = prefix;
    }

    public Integer getExpiration() {
        return expiration;
    }

    public void setExpiration(Integer expiration) {
        this.expiration = expiration;
    }

    public SecretKey getSignInSecretKey() {
        return Keys.hmacShaKeyFor(this.key.getBytes());
    }

    public String getAuthorization() {
        return HttpHeaders.AUTHORIZATION;
    }
}
