package com.example.security_oauth2.MyAbstractTokenGranter;

import cn.hutool.core.util.ObjectUtil;
import com.example.security_oauth2.UserDetailService.MyUserDetailService;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.*;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.provider.*;
import org.springframework.security.oauth2.provider.token.AbstractTokenGranter;
import org.springframework.security.oauth2.provider.token.AuthorizationServerTokenServices;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * SpringSecurity Oauth2默认提供了四种认证方式,如果需要其他认证方式需要自定义登录认证方式
 * AuthorizationServerEndpointsConfigurer.List<TokenGranter> getDefaultTokenGranters()方法中写死了那四种授权模式
 * 默认的四种认证方式都集成了抽象类AbstractTokenGranter,所以只需要继承抽象类AbstractTokenGranter,
 * 并且源码调用getDefaultTokenGranters()方法的时候我们手动把这个类加进去,在授权服务器配置中加入
 * 模仿ResourceOwnerPasswordTokenGranter,密码模式来完成自定义认证模式
 */
public class MyTokenGranter extends AbstractTokenGranter {

    private static final String GRANT_TYPE = "my_type";

    private MyUserDetailService myUserDetailService;

//    private RedisTemplate<String, String> redisTemplate;

    //用构造方法对该类中需要用到的服务注入
    public MyTokenGranter(AuthorizationServerTokenServices tokenServices,
                          ClientDetailsService clientDetailsService,
                          OAuth2RequestFactory requestFactory,
                          MyUserDetailService myUserDetailService
                          //,RedisTemplate<String, String> redisTemplate
    ) {
        super(tokenServices, clientDetailsService, requestFactory, GRANT_TYPE);
        this.myUserDetailService = myUserDetailService;
//        this.redisTemplate = redisTemplate;
    }

    /**
     * 具体的认证流程在该方法中实现
     * 下面以短信验证法作为例子
     */
    @Override
    protected OAuth2Authentication getOAuth2Authentication(ClientDetails client, TokenRequest tokenRequest) {
        //固定写法
        Map<String, String> parameters = new LinkedHashMap<String, String>(tokenRequest.getRequestParameters());

        // 客户端提交的手机号码
        String phone = parameters.get("phone");

        // 客户端提交的验证码
        String code = parameters.get("code");

        //自定义校验

        //根据手机号查询用户信息
        UserDetails userDetails = myUserDetailService.loadUserByUsername(phone);


        AbstractAuthenticationToken userAuth = new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());

        userAuth.setDetails(parameters);

        OAuth2Request oAuth2Request = getRequestFactory().createOAuth2Request(client, tokenRequest);
        return new OAuth2Authentication(oAuth2Request, userAuth);
    }
}
