package com.sparta.apigatewayservice.filter;

import com.sparta.apigatewayservice.exception.CustomException;
import com.sparta.apigatewayservice.jwt.JwtUtil;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

@Component
@Slf4j
public class AuthorizationFilter extends AbstractGatewayFilterFactory<AuthorizationFilter.Config> {

    private final JwtUtil jwtUtil;

    public AuthorizationFilter(JwtUtil jwtUtil) {
        super(Config.class);
        this.jwtUtil = jwtUtil;
    }

    public static class Config {}

    @Override
    public GatewayFilter apply(Config config) {
        return (exchange, chain) -> {
            ServerHttpRequest request = exchange.getRequest();
            log.info("Method : {}, Request URI: {}", request.getMethod(), request.getURI());

            String token;
            try {
                token = jwtUtil.getAccessTokenFromHeader(request);
            } catch (CustomException e) {
                log.error(e.getErrorType().getMessage());
                return onError(exchange, e);
            }

            try {
                jwtUtil.validateToken(token);
            } catch (CustomException e) {
                log.error(e.getErrorType().getMessage());
                return onError(exchange, e);
            }

            return chain.filter(exchange);
        };
    }

    //에러 처리
    //Mono : Spring MVC -> Spring WebFlux에서 사용하는 비동기식 데이터 처리타입(Mono:단일, Flux:복수)
    private Mono<Void> onError(ServerWebExchange exchange, CustomException e) {
        ServerHttpResponse response = exchange.getResponse();
        response.setStatusCode(e.getErrorType().getHttpStatus());

        DataBuffer buffer = response.bufferFactory().wrap(e.getErrorType().getMessage().getBytes());

        return response.writeWith(Flux.just(buffer));
//        return response.setComplete();
    }
}
