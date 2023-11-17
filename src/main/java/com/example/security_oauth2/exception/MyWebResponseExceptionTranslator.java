
package com.example.security_oauth2.exception;

import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.common.DefaultThrowableAnalyzer;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.exceptions.ClientAuthenticationException;
import org.springframework.security.oauth2.common.exceptions.InsufficientScopeException;
import org.springframework.security.oauth2.common.exceptions.InvalidGrantException;
import org.springframework.security.oauth2.common.exceptions.OAuth2Exception;
import org.springframework.security.oauth2.provider.error.WebResponseExceptionTranslator;
import org.springframework.security.web.util.ThrowableAnalyzer;
import org.springframework.web.HttpRequestMethodNotSupportedException;


/**
 * 异常处理,重写oauth 默认实现
 * 授权服务器中的错误处理使用标准的Spring MVC功能，即@ExceptionHandler端点本身中的方法。
 * 但是其原生的异常信息可能与我们实际使用的异常处理不一致，需要进行转义。
 * 可以自定义WebResponseExceptionTranslator，向授权端点提供异常处理，这是更改响应异常处理的最佳方法。
 * 实现WebResponseExceptionTranslator接口，自定义授权端点异常处理
 */
@Slf4j
public class MyWebResponseExceptionTranslator implements WebResponseExceptionTranslator {

	private ThrowableAnalyzer throwableAnalyzer = new DefaultThrowableAnalyzer();

	@Override
	public ResponseEntity<OAuth2Exception> translate(Exception e) {

		// Try to extract a SpringSecurityException from the stacktrace
		Throwable[] causeChain = throwableAnalyzer.determineCauseChain(e);

		Exception ase = (AuthenticationException) throwableAnalyzer.getFirstThrowableOfType(AuthenticationException.class,
				causeChain);
		if (ase != null) {
			return handleOAuth2Exception(new UnauthorizedException(e.getMessage(), e));
		}

		ase = (AccessDeniedException) throwableAnalyzer
				.getFirstThrowableOfType(AccessDeniedException.class, causeChain);
		if (ase != null) {
			return handleOAuth2Exception(new ForbiddenException(ase.getMessage(), ase));
		}

		ase = (InvalidGrantException) throwableAnalyzer
				.getFirstThrowableOfType(InvalidGrantException.class, causeChain);
		if (ase != null) {
			return handleOAuth2Exception(new InvalidException(ase.getMessage(), ase));
		}

		ase = (HttpRequestMethodNotSupportedException) throwableAnalyzer
				.getFirstThrowableOfType(HttpRequestMethodNotSupportedException.class, causeChain);
		if (ase != null) {
			return handleOAuth2Exception(new MethodNotAllowedException(ase.getMessage(), ase));
		}

		ase = (OAuth2Exception) throwableAnalyzer.getFirstThrowableOfType(
				OAuth2Exception.class, causeChain);

		if (ase != null) {
			return handleOAuth2Exception((OAuth2Exception) ase);
		}

		return handleOAuth2Exception(new ServerErrorException(HttpStatus.INTERNAL_SERVER_ERROR.getReasonPhrase(), e));

	}

	private ResponseEntity<OAuth2Exception> handleOAuth2Exception(OAuth2Exception e) {

		int status = e.getHttpErrorCode();
		HttpHeaders headers = new HttpHeaders();
		headers.set(HttpHeaders.CACHE_CONTROL, "no-store");
		headers.set(HttpHeaders.PRAGMA, "no-cache");
		if (status == HttpStatus.UNAUTHORIZED.value() || (e instanceof InsufficientScopeException)) {
			headers.set(HttpHeaders.WWW_AUTHENTICATE, String.format("%s %s", OAuth2AccessToken.BEARER_TYPE, e.getSummary()));
		}

		// 客户端异常直接返回客户端,不然无法解析
		if (e instanceof ClientAuthenticationException) {
			return new ResponseEntity<>(e, headers,
					HttpStatus.valueOf(status));
		}
		return new ResponseEntity<>(new MyAuth2Exception(e.getMessage(), e.getOAuth2ErrorCode()), headers,
				HttpStatus.valueOf(status));

	}
}
