package com.example.security_oauth2.AuthorizationServer;

import cn.hutool.core.util.StrUtil;
import com.example.security_oauth2.CheckToken.MyUserAuthenticationConverter;
import com.example.security_oauth2.MyAbstractTokenGranter.MyTokenGranter;
import com.example.security_oauth2.MyAuthentication.MyGranter;
import com.example.security_oauth2.TokenStoreConfig.MyAuthenticationKeyGenerator;
import com.example.security_oauth2.UserDetailService.MyUserDetailService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.CompositeTokenGranter;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.TokenGranter;
import org.springframework.security.oauth2.provider.token.DefaultAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.DefaultAuthenticationKeyGenerator;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.InMemoryTokenStore;
import org.springframework.security.oauth2.provider.token.store.redis.RedisTokenStore;
import sun.security.util.SecurityConstants;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

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

    @Autowired
    private MyUserDetailService myUserDetailService;

    @Autowired
    private RedisConnectionFactory redisConnectionFactory;

//    @Autowired
//    private RedisTemplate<String,String> redisTemplate;


    /**
     * 令牌端点的安全约束:endpoint可以定义一些安全上的约束等
     * 对应于配置AuthorizationServer安全认证的相关信息，创建ClientCredentialsTokenEndpointFilter核心过滤器
     */
    @Override
    public void configure(AuthorizationServerSecurityConfigurer security) throws Exception {
        security
                //开启/oauth/token_key验证端口认证权限访问
                .tokenKeyAccess("isAuthenticated()")
                //开启/oauth/check_token验证端口认证权限访问
                .checkTokenAccess("isAuthenticated()")
                //允许表单认证 让/oauth/token支持client_id以及client_secret作登录认证
                .allowFormAuthenticationForClients();

    }


    /**
     * 客户端配置：这里我们先使用内存的方式构造死数据进行入门，后续我们需要从数据库中读取客户端信息
     * 配置OAuth2的客户端相关信息
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
     * 配置身份认证器，配置认证方式，TokenStore，TokenGranter，OAuth2RequestFactory
     */
    @Override
    public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {


        DefaultAccessTokenConverter defaultAccessTokenConverter=new DefaultAccessTokenConverter();
        defaultAccessTokenConverter.setUserTokenConverter(new MyUserAuthenticationConverter());
        endpoints
                //密码模式需要配置注入的authenticationManager，后续深入在解释为什么需要注入这个
                .authenticationManager(authenticationManager)
//                .accessTokenConverter(defaultAccessTokenConverter)
                //将自定义的认证模式加入到配置中
                .tokenGranter(tokenGranter(endpoints))
                //token，这里目前我们简单使用内存的方式
                .tokenStore(new InMemoryTokenStore());
    }

    /**
     * 添加自定义授权类型
     *
     * @return List<TokenGranter>
     */
    private TokenGranter tokenGranter(AuthorizationServerEndpointsConfigurer endpoints) {

        // endpoints.getTokenGranter() 获取SpringSecurity OAuth2.0 现有的授权类型
        List<TokenGranter> granters = new ArrayList<TokenGranter>(Collections.singletonList(endpoints.getTokenGranter()));

        // 构建短信验证授权类型
        MyTokenGranter myTokenGranter = new MyTokenGranter(endpoints.getTokenServices(), endpoints.getClientDetailsService(),
                endpoints.getOAuth2RequestFactory(),myUserDetailService
                //,redisTemplate
        );

        MyGranter myGranter = new MyGranter(authenticationManager,endpoints.getTokenServices(), endpoints.getClientDetailsService(),
                endpoints.getOAuth2RequestFactory());
        // 向集合中添加短信授权类型
        granters.add(myTokenGranter);
        granters.add(myGranter);
        // 返回所有类型
        return new CompositeTokenGranter(granters);
    }

    /**
     *  TokenStore 是一个用于存储和管理令牌（token）的组件或系统。
     *  它通常被用于身份验证和授权的过程中。
     *  TokenStore 可以将令牌存储在内存中、数据库中或其他持久化存储介质中，
     *  并为应用程序提供相关的操作接口，如创建令牌、验证令牌、刷新令牌等。
     *  下面是将token存在redis的配置
     */
    @Bean
    public TokenStore tokenStore() {
        //创建redisTokenStore对象
        RedisTokenStore tokenStore = new RedisTokenStore(redisConnectionFactory);
        //设置token在redis中的前缀(xxx:xxx)可实现文件夹格式
        tokenStore.setPrefix("前缀");

        //设置token的生成规则,默认使用DefaultAuthenticationKeyGenerator
        //DefaultAuthenticationKeyGenerator根据client_id,scope,username组成个Map进而生成一个key
        //RedisTokenStore根据生成的key转换成byte[]生成token
        //这样会造成当username的值相同是,任何登录方式生成的token都一样,如果想实现token值也不一样
        //需要自定义一个类继承DefaultAuthenticationKeyGenerator进行扩展,可以将认证类型也加入到Map中
        //将自定义的类加入到配置中
        tokenStore.setAuthenticationKeyGenerator(new MyAuthenticationKeyGenerator() {
            //这里使用匿名内部类,重写extractKey方法,对自定义生成的key再进行扩展
            @Override
            public String extractKey(OAuth2Authentication authentication) {
                return super.extractKey(authentication)+"对自定义生成的key再进行扩展";
            }
        });
        return tokenStore;
    }


}
