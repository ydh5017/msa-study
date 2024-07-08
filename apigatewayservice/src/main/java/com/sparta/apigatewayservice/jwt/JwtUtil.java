package com.sparta.apigatewayservice.jwt;

import com.sparta.apigatewayservice.enums.ErrorType;
import com.sparta.apigatewayservice.exception.CustomException;
import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import java.security.Key;
import java.util.Base64;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

@Component
@RequiredArgsConstructor
@Slf4j(topic = "JwtUtil")
public class JwtUtil {

    // access 토큰 헤더
    public static final String AUTH_ACCESS_HEADER = "AccessToken";
    // refresh 토큰 헤더
    public static final String AUTH_REFRESH_HEADER = "RefreshToken";
    // 사용자 권한
    public static final String AUTHORIZATION_KEY = "auth";
    // 토큰 식별자
    public static final String BEARER_PREFIX = "Bearer ";
    // access 토큰 만료 시간 (30분)
    private final long ACCESS_TOKEN_EXPIRE_TIME = 30 * 60 * 1000L;
    // refresh 토큰 만료 시간 (2주)
    private final long REFRESH_TOKEN_EXPIRE_TIME = 14 * 24 * 60 * 60 * 1000L;
    // 로그아웃 refresh 토큰 블랙리스트
    private Set<String> blacklist = ConcurrentHashMap.newKeySet();

    @Value("${jwt.secret.key}")
    private String secretKey;
    private Key key;
    private final SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.HS256;

    @PostConstruct
    public void init() {
        byte[] bytes = Base64.getDecoder().decode(secretKey);
        key = Keys.hmacShaKeyFor(bytes);
    }

    // 헤더에서 access 토큰 가져오기
    public String getAccessTokenFromHeader(ServerHttpRequest request) {
        if (!request.getHeaders().containsKey(AUTH_ACCESS_HEADER)) {
            throw new CustomException(ErrorType.NOT_FOUND_AUTHENTICATION_INFO);
        }

        String accessToken = request.getHeaders().get(AUTH_ACCESS_HEADER).get(0);

        if (StringUtils.hasText(accessToken) && accessToken.startsWith(BEARER_PREFIX)) {
            return accessToken.substring(BEARER_PREFIX.length());
        }

        return null;
    }

    // 헤더에서 refresh 토큰 가져오기
    public String getRefreshTokenFromHeader(ServerHttpRequest request) {
        if (!request.getHeaders().containsKey(AUTH_REFRESH_HEADER)) {
            throw new CustomException(ErrorType.NOT_FOUND_AUTHENTICATION_INFO);
        }

        String accessToken = request.getHeaders().get(AUTH_REFRESH_HEADER).get(0);

        if (StringUtils.hasText(accessToken) && accessToken.startsWith(BEARER_PREFIX)) {
            return accessToken.substring(BEARER_PREFIX.length());
        }
        return null;
    }

    // 토큰 검증
    public boolean validateToken(String token) {
        try {
            Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token);
            return true;
        } catch (SecurityException | MalformedJwtException | SignatureException e) {
            log.error("Invalid JWT signature, 유효하지 않는 JWT 서명 입니다.");
            throw new CustomException(ErrorType.INVALID_JWT);
        } catch (ExpiredJwtException e) {
            log.error("Expired JWT token, 만료된 JWT token 입니다.");
            throw new CustomException(ErrorType.EXPIRED_JWT);
//            return false;
        } catch (UnsupportedJwtException e) {
            log.error("Unsupported JWT token, 지원되지 않는 JWT 토큰 입니다.");
            throw new CustomException(ErrorType.INVALID_JWT);
        } catch (IllegalArgumentException e) {
            log.error("JWT claims is empty, 잘못된 JWT 토큰 입니다.");
            throw new CustomException(ErrorType.INVALID_JWT);
        }
    }
}
