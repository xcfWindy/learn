

package com.example.security_oauth2.exception;

import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import lombok.Getter;
import org.springframework.security.oauth2.common.exceptions.OAuth2Exception;

/**
 * 自定义OAuth2Exception
 */
@JsonSerialize(using = MyAuth2ExceptionSerializer.class)
public class MyAuth2Exception extends OAuth2Exception {
	@Getter
	private String errorCode;

	public MyAuth2Exception(String msg) {
		super(msg);
	}

	public MyAuth2Exception(String msg, Throwable t) {
		super(msg,t);
	}

	public MyAuth2Exception(String msg, String errorCode) {
		super(msg);
		this.errorCode = errorCode;
	}
}
