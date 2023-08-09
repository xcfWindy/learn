package com.example.security_oauth2.UserDetailService;

import com.example.security_oauth2.AuthorizationServer.ClientInfo;
import com.example.security_oauth2.ResourceOwner.UserInfo;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.util.ObjectUtils;

import java.util.ArrayList;
import java.util.List;

@Service
public class MyUserDetailServiceImpl implements MyUserDetailService {


    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        //根据账号去数据库中查询
        UserInfo userInfo = new UserInfo();
        if (!ObjectUtils.isEmpty(userInfo)){
            List<SimpleGrantedAuthority> authorities = new ArrayList<>();
            // 设置登录账号的角色 角色必须以ROLE_开头
            authorities.add(new SimpleGrantedAuthority("ROLE_USER"));
            // 说明账号存在 {noop} 非加密的使用
            UserDetails user = new User(userInfo.getUserName(),"{noop}"+userInfo.getPassWord(),authorities);
            return user;
            //我们在实际项目中因为用户的不同操作，可能会给出不同的状态，比如正常，冻结等，SpringSecurity也支持，我们来看下，如何实现。
            /**
             * User(String username, String password, boolean enabled, boolean accountNonExpired,
             * 			boolean credentialsNonExpired, boolean accountNonLocked,
             * 			Collection<? extends GrantedAuthority> authorities)
             * 		在认证的时候使用User对象的另一个构造器就可以了
             * 	boolean enabled  是否可用
             * 	boolean accountNonExpired  账号是否失效
             * 	boolean credentialsNonExpired 秘钥是否失效
             * 	boolean accountNonLocked 账号是否锁定
             */
        }
        // 返回null 默认表示账号不存在
        return null;
    }
}
