package com.sparta.apigatewayservice.enums;


import lombok.AllArgsConstructor;
import lombok.Getter;
import org.springframework.http.HttpStatus;

@Getter
@AllArgsConstructor
public enum ErrorType {
    // user
    DUPLICATE_ACCOUNT_ID(HttpStatus.LOCKED, "이미 아이디가 존재합니다."),
    DUPLICATE_EMAIL(HttpStatus.LOCKED, "이미 이메일이 존재합니다."),
    INVALID_EMAIL(HttpStatus.LOCKED, "이메일을 잘못 입력하였습니다."),
    INVALID_ACCOUNT_ID(HttpStatus.UNAUTHORIZED, "아이디가 일치하지 않습니다."),
    INVALID_PASSWORD(HttpStatus.UNAUTHORIZED, "비밀번호가 일치하지 않습니다."),
    DEACTIVATE_USER(HttpStatus.FORBIDDEN, "이미 탈퇴한 회원입니다."),
    DUPLICATE_PASSWORD(HttpStatus.LOCKED, "중복된 비밀번호입니다."),
    NO_AUTHENTICATION(HttpStatus.FORBIDDEN, "권한이 없습니다."),
    NOT_FOUND_USER(HttpStatus.NOT_FOUND, "회원을 찾을 수 없습니다."),
    REQUIRES_LOGIN(HttpStatus.LOCKED, "로그인이 필요한 서비스입니다."),
    EMAIL_VERIFICATION_REQUIRED(HttpStatus.LOCKED, "이메일 인증이 필요합니다."),

    // email_verify
    EXPIRED_AUTH_NUM(HttpStatus.LOCKED, "이메일 인증 코드가 만료 되었습니다."),
    WRONG_AUTH_NUM(HttpStatus.LOCKED, "잘못된 인증번호 입니다."),
    VERIFIED_EMAIL(HttpStatus.LOCKED, "이미 이메일 검증을 완료하였습니다."),

    // newsfeed
    NOT_FOUND_POST(HttpStatus.NOT_FOUND, "게시글이 존재하지 않습니다."),

    // comment
    NOT_FOUND_COMMENT(HttpStatus.NOT_FOUND, "댓글이 존재하지 않습니다."),

    // DUPLICATED_USER(HttpStatus.LOCKED, "중복된 사용자가 존재합니다."),
    // DUPLICATED_EMAIL(HttpStatus.LOCKED, "중복된 Email 입니다."),

    // JWT
    INVALID_REFRESH_TOKEN(HttpStatus.UNAUTHORIZED, "유효하지 않은 리프레시 토큰입니다. 다시 로그인 해주세요."),
    NOT_FOUND_AUTHENTICATION_INFO(HttpStatus.NOT_FOUND, "인증 정보를 찾을 수 없습니다."),
    INVALID_JWT(HttpStatus.UNAUTHORIZED, "유효하지 않는 JWT 입니다."),
    EXPIRED_JWT(HttpStatus.FORBIDDEN, "만료된 JWT 입니다."),
    LOGGED_OUT_TOKEN(HttpStatus.FORBIDDEN, "이미 로그아웃된 토큰입니다."),

    ALREADY_LIKED(HttpStatus.CONFLICT, "이미 좋아요를 했습니다."),
    CANNOT_LIKE_OWN_CONTENT(HttpStatus.FORBIDDEN, "자신의 콘텐츠에 좋아요를 할 수 없습니다."),
    NON_EXISTENT_CONTENT_TYPE(HttpStatus.NOT_FOUND, "존재하지 않는 콘텐츠 타입입니다."),
    NOT_FOUND_LIKE(HttpStatus.NOT_FOUND, "좋아요가 존재하지 않습니다."),

    // file
    NOT_IMGFILE(HttpStatus.UNSUPPORTED_MEDIA_TYPE, "이미지 파일만 업로드할 수 있습니다."),
    DOES_NOT_EXIST_FILE(HttpStatus.NOT_FOUND, "파일이 존재하지 않습니다."),
    IMAGE_LIMIT_EXCEEDED(HttpStatus.PAYLOAD_TOO_LARGE, "이미지 파일의 최대 용량은 10MB입니다."),
    VIDEO_LIMIT_EXCEEDED(HttpStatus.PAYLOAD_TOO_LARGE, "비디오 파일의 최대 용량은 200MB입니다."),
    UNSUPPORTED_MEDIA_TYPE(HttpStatus.UNSUPPORTED_MEDIA_TYPE, "지원하지 않는 미디어 유형입니다."),
    FILE_COUNT_EXCEEDED(HttpStatus.PAYLOAD_TOO_LARGE, "한 게시글에 최대 5개의 미디어만 업로드 할 수 있습니다."),

    // AWS
    UPLOAD_FAILED(HttpStatus.GATEWAY_TIMEOUT, "파일 업로드에 실패하였습니다.");

    private final HttpStatus httpStatus;
    private final String message;
}
