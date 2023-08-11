package com.example.security_oauth2.CheckToken;

import org.springframework.boot.autoconfigure.security.SecurityProperties;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.oauth2.provider.token.UserAuthenticationConverter;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * 扩展checkToken返回结果
 * 在授权服务器的endpoints配置中加上此类
 * DefaultAccessTokenConverter defaultAccessTokenConverter=new DefaultAccessTokenConverter();
 * defaultAccessTokenConverter.setUserTokenConverter(new MyUserAuthenticationConverter());
 * endpoints.accessTokenConverter(defaultAccessTokenConverter)
 * 此类的convertUserAuthentication()方法在DefaultAccessTokenConverter的convertAccessToken()方法中调用
 * private UserAuthenticationConverter userTokenConverter = new DefaultUserAuthenticationConverter();
 * response.putAll(userTokenConverter.convertUserAuthentication(authentication.getUserAuthentication()));
 * 默认执行DefaultUserAuthenticationConverter类的convertUserAuthentication()方法,添加user_name authorities
 * 自定义UserAuthenticationConverter接口的实现类后不执DefaultUserAuthenticationConverter的方法需要重写添加user_name authorities
 * convertUserAuthentication()方法可以在返回的Map集合中添加自己需要的信息
 */
public class MyUserAuthenticationConverter implements UserAuthenticationConverter {
    @Override
    public Map<String, ?> convertUserAuthentication(Authentication authentication) {
        Map<String, Object> response = new LinkedHashMap<String, Object>();
        response.put(USERNAME, authentication.getName());
        Object principal = authentication.getPrincipal();
        //后续转换成自己定义的对象,可以获取对象中的信息，但是不能改变对象的属性
        if (principal instanceof SecurityProperties.User){
            SecurityProperties.User user= (SecurityProperties.User) principal;
            response.put("key", "自定义内容");
        }


        if (authentication.getAuthorities() != null && !authentication.getAuthorities().isEmpty()) {
            response.put(AUTHORITIES, AuthorityUtils.authorityListToSet(authentication.getAuthorities()));
        }
        return response;
    }

    @Override
    public Authentication extractAuthentication(Map<String, ?> map) {
        return null;
    }
}
