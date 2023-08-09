package com.example.security_oauth2.config;

import com.example.security_oauth2.ResourceOwner.UserInfo;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;


/**
 * spring security配置
 */
@Order(1)
@EnableWebSecurity
@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    /**
     * 自定义用户认证逻辑
     */
//    @Autowired
//    private UserDetailsService userDetailsService;

    /**
     * 认证失败处理类
     */


    /**
     * 退出处理类
     */


    /**
     * token认证过滤器
     */


    /**
     * 跨域过滤器
     */

    /**
     * 解决 无法直接注入 AuthenticationManager
     */
    @Bean
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }

    /**
     * 强散列哈希加密实现 动态加盐
     */
    @Bean
    public BCryptPasswordEncoder bCryptPasswordEncoder() {

        return new BCryptPasswordEncoder();
    }

    /**
     * 认证管理器配置方法
     * 认证服务器中注入的authenticationManager就是从这里来的
     * AuthenticationManagerBuilder（身份验证管理生成器）
     * 用来配置认证管理器AuthenticationManager。说白了就是所有 UserDetails 相关的它都管，包含 PasswordEncoder 密码等。
     */
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        UserInfo userInfo = new UserInfo();
        auth.inMemoryAuthentication()
                .withUser(userInfo.getUserName())
                .password("{noop}" + userInfo.getPassWord())//{noop}非加密的方式
                .roles(userInfo.getRole());

        //在这里关联数据库和security
//        auth.userDetailsService(userDetailsService).passwordEncoder(bCryptPasswordEncoder());
    }

    /***
     * 核心过滤器配置方法
     * WebSecurity（WEB安全）
     * 用来配置 WebSecurity ,而 WebSecurity 是基于 Servlet Filter 用来配置 springSecurityFilterChain。
     * 而 springSecurityFilterChain 又被委托给了 Spring Security 核心过滤器 Bean DelegatingFilterProxy。
     * 相关逻辑你可以在 WebSecurityConfiguration 中找到。
     * 我们一般不会过多来自定义 WebSecurity , 使用较多的使其ignoring() 方法用来忽略 Spring Security 对静态资源的控制。
     */
    @Override
    public void configure(WebSecurity web) throws Exception {
        super.configure(web);
        //解决静态资源被拦截的问题
        web.ignoring();
    }

    /**
     * anyRequest          |   匹配所有请求路径
     * access              |   SpringEl表达式结果为true时可以访问
     * anonymous           |   匿名可以访问
     * denyAll             |   用户不能访问
     * fullyAuthenticated  |   用户完全认证可以访问（非remember-me下自动登录）
     * hasAnyAuthority     |   如果有参数，参数表示权限，则其中任何一个权限可以访问
     * hasAnyRole          |   如果有参数，参数表示角色，则其中任何一个角色可以访问
     * hasAuthority        |   如果有参数，参数表示权限，则其权限可以访问
     * hasIpAddress        |   如果有参数，参数表示IP地址，如果用户IP和参数匹配，则可以访问
     * hasRole             |   如果有参数，参数表示角色，则其角色可以访问
     * permitAll           |   用户可以任意访问
     * rememberMe          |   允许通过remember-me登录的用户访问
     * authenticated       |   用户登录后可访问
     * httpBasic()         |   启用 HTTP Basic 认证
     */
    /**
     * 安全过滤器链配置方法
     * HttpSecurity（HTTP请求安全处理）
     * HttpSecurity 用于构建一个安全过滤器链 SecurityFilterChain 。SecurityFilterChain 最终被注入核心过滤器 。
     * HttpSecurity 有许多我们需要的配置。我们可以通过它来进行自定义安全访问策略。
     */
    @Override
    protected void configure(HttpSecurity http) throws Exception {

        http     // 配置登录页并允许访问
                .formLogin().permitAll()
                .and().logout().logoutUrl("/logout").logoutSuccessUrl("/")
                .and().authorizeRequests().antMatchers("/oauth/**", "/login/**", "/logout/**").permitAll()
                // 其余所有请求全部需要鉴权认证
                .anyRequest().authenticated()
                // 关闭跨域保护;
                .and().csrf().disable();

//        http
//                // CSRF禁用，因为不使用session
//                .csrf().disable()
//                // 认证失败处理类
////                .exceptionHandling().authenticationEntryPoint(unauthorizedHandler).and()
//                // 基于token，所以不需要session
//                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS).and()
//                // 过滤请求
//                .authorizeRequests()
//                // 对于登录login 验证码captchaImage 允许匿名访问
//                .antMatchers("/login", "/captchaImage").anonymous()
//                .antMatchers(
//                        HttpMethod.GET,
//                        "/*.html",
//                        "/**/*.html",
//                        "/**/*.css",
//                        "/**/*.js"
//                ).permitAll()
//                .antMatchers("/**").permitAll()
//                // 除上面外的所有请求全部需要鉴权认证
//                .anyRequest().authenticated()
//                .and()
//                //将安全标头添加到响应,比如说简单的 XSS 保护
//                .headers().frameOptions().disable();
//        http.logout().logoutUrl("/logout").logoutSuccessHandler(logoutSuccessHandler);
        // 添加JWT filter
//        http.addFilterBefore(authenticationTokenFilter, UsernamePasswordAuthenticationFilter.class);
        // 添加CORS filter
//        http.addFilterBefore(corsFilter, JwtAuthenticationTokenFilter.class);
//        http.addFilterBefore(corsFilter, LogoutFilter.class);

    }
}
