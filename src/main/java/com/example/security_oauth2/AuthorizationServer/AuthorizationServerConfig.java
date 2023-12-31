package com.example.security_oauth2.AuthorizationServer;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.token.store.InMemoryTokenStore;

/**
 * 搭建授权服务器
 * 第二步
 * 创建授权服务器
 * 认证服务器配置
 * 在成功验证资源所有者且获得授权后颁发访问令牌给客户端的服务器，使得授权客户端应用能够访问资源拥有者所拥有的资源
 */
@Configuration
@EnableAuthorizationServer
public class AuthorizationServerConfig extends AuthorizationServerConfigurerAdapter {
    /**
     * 认证相关的核心接口，也是发起认证的出发点
     * <p>
     * 尝试对传递的Authentication对象进行身份验证
     * 如果验证成功，则返回完全填充的Authentication对象（包括授予的权限）
     * AuthenticationManager必须遵守以下关于异常的约定：
     * 如果帐户被禁用并且AuthenticationManager可以测试此状态，则必须抛出DisabledException
     * 如果帐户被锁定并且AuthenticationManager可以测试帐户锁定，则必须抛出LockedException
     * 如果提供了不正确的凭证（比如密码），则必须抛出BadCredentialsException
     * 参数：authentication - 身份验证请求的封装
     * 返回：一个完全经过身份验证的对象，包括凭证
     */
    @Autowired
    private AuthenticationManager authenticationManager;


    /**
     * 令牌端点的安全约束:endpoint可以定义一些安全上的约束等
     */
    @Override
    public void configure(AuthorizationServerSecurityConfigurer security) throws Exception {
        security
                //开启/oauth/token_key验证端口认证权限访问
                .tokenKeyAccess("isAuthenticated()")
                //开启/oauth/check_token验证端口认证权限访问
                .checkTokenAccess("isAuthenticated()")
                //允许表单认证
                .allowFormAuthenticationForClients();

    }


    /**
     * 客户端配置：这里我们先使用内存的方式构造死数据进行入门，后续我们需要从数据库中读取客户端信息
     */
    @Override
    public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
        //使用我们构建的客户端信息，将其写入到内存中
        ClientInfo clientInfo = new ClientInfo();
        clients
                //使用内存存储
                .inMemory()
                //标记客户端id
                .withClient(clientInfo.getClientId())
                //客户端安全码    需要注意这里存储的数据是通过BCryptPasswordEncoder进行加密后的数据
                .secret("{noop}" + clientInfo.getClientSecret())
                //为true 直接自动授权成功返回code
                .autoApprove(true)
                //重定向uri
                .redirectUris("https://www.baidu.com/")
                //允许授权范围
                .scopes(clientInfo.getScop())
                //token 时间秒  Validity 有效
                .accessTokenValiditySeconds(clientInfo.getTokenValid())
                //刷新token 时间 秒
                .refreshTokenValiditySeconds(clientInfo.getFlushTokenValid())
                //允许授权类型
                .authorizedGrantTypes(clientInfo.getGrantTypes());
    }

    /**
     * 配置令牌访问端点:定义token的相关endpoint，以及token如何存取，以及客户端支持哪些类型的token
     */
    @Override
    public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
        endpoints
                //密码模式需要配置注入的authenticationManager，后续深入在解释为什么需要注入这个
                .authenticationManager(authenticationManager)
                //token，这里目前我们简单使用内存的方式
                .tokenStore(new InMemoryTokenStore());
    }

}
