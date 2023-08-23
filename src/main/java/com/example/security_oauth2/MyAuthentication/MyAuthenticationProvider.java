package com.example.security_oauth2.MyAuthentication;

import lombok.Setter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;

/**
 * 新增一个 AuthenticationProvider 实现类 MyAuthenticationProvider 实现授权的逻辑
 */
@Setter
public class MyAuthenticationProvider implements AuthenticationProvider {

    @Autowired
    private UserDetailsService userDetailsService;

    private RedisTemplate<String, String> redisTemplate;




    /**
     * 在这个方法里进行登录逻辑的校验
     */
    @Override
    public Authentication authenticate(Authentication authentication) {

        MyAuthenticationToken authenticationToken = (MyAuthenticationToken) authentication;


        // 获取authentication参数的principal属性作为手机号
        String phone = (String) authenticationToken.getPrincipal();

        // 获取authentication参数的credentials属性作为短信验证码
        String code = authentication.getCredentials().toString();

        // 调用自定义的通过principal(Token对象中的变量)获取用户信息方法
        UserDetails user = userDetailsService.loadUserByUsername(phone);


        if (null == user) {
            throw new InternalAuthenticationServiceException("openId错误");
        }

        // 认证成功则返回一个MobilePhoneAuthenticationToken实例对象，principal属性为较为完整的用户信息
        MyAuthenticationToken authenticationResult = new MyAuthenticationToken(user, user.getAuthorities());
        authenticationResult.setDetails(authenticationToken.getDetails());
        return authenticationResult;
    }

    /**
     * 只支持自定义的MyAuthenticationToken类的认证
     */
    @Override
    public boolean supports(Class<?> authentication) {
        return MyAuthenticationToken.class.isAssignableFrom(authentication);
    }

}

