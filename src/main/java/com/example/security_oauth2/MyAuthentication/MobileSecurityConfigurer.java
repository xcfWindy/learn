
package com.example.security_oauth2.MyAuthentication;

import lombok.Getter;
import lombok.Setter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.config.annotation.SecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.DefaultSecurityFilterChain;


/**
 * 自定义手机号登录配置入口
 */
@Getter
@Setter
public class MobileSecurityConfigurer extends SecurityConfigurerAdapter<DefaultSecurityFilterChain, HttpSecurity> {

	@Autowired
	private UserDetailsService userDetailsService;

	@Autowired
	private RedisTemplate<String,String> redisTemplate;

	@Override
	public void configure(HttpSecurity http) {

		MyAuthenticationProvider myAuthenticationProvider = new MyAuthenticationProvider();
		myAuthenticationProvider.setUserDetailsService(userDetailsService);
		myAuthenticationProvider.setRedisTemplate(redisTemplate);
		http.authenticationProvider(myAuthenticationProvider);

	}
}
