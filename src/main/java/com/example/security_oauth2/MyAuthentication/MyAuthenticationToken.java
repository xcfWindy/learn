package com.example.security_oauth2.MyAuthentication;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.SpringSecurityCoreVersion;

import java.util.Collection;

/**
 * 需要放在公共的包下面,以手机验证码登录举例
 */
public class MyAuthenticationToken extends AbstractAuthenticationToken {

    private static final long serialVersionUID = SpringSecurityCoreVersion.SERIAL_VERSION_UID;

    // 登录身份，这里是手机号
    private final Object principal;

    // 登录凭证，这里是短信验证码
    private Object credentials;


    public MyAuthenticationToken(String phone,String code) {
        super(null);
        this.principal = phone;
        this.credentials = code;
        setAuthenticated(false);
    }


    public MyAuthenticationToken(Object principal,
                                 Collection<? extends GrantedAuthority> authorities) {
        super(authorities);
        this.principal = principal;
        super.setAuthenticated(true);
    }

    /**
     * 构造方法
     * @param authorities 权限集合
     * @param principal 登录身份
     * @param credentials 登录凭据
     */
    public MyAuthenticationToken(Collection<? extends GrantedAuthority> authorities, Object principal, Object credentials) {
        super(authorities);
        this.principal = principal;
        this.credentials = credentials;
        super.setAuthenticated(true);
    }



    @Override
    public Object getCredentials() {
        return this.credentials;
    }

    @Override
    public Object getPrincipal() {
        return this.principal;
    }

    // 不允许通过set方法设置认证标识
    @Override
    public void setAuthenticated(boolean isAuthenticated) {
        if (isAuthenticated) {
            throw new IllegalArgumentException(
                    "Cannot set this token to trusted - use constructor which takes a GrantedAuthority list instead");
        }
        super.setAuthenticated(false);
    }

    // 擦除登录凭据
    @Override
    public void eraseCredentials() {
        super.eraseCredentials();
    }
}
