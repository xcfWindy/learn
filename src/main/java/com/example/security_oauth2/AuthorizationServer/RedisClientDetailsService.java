package com.example.security_oauth2.AuthorizationServer;

import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.provider.client.JdbcClientDetailsService;
import org.springframework.stereotype.Service;

import javax.sql.DataSource;

/**
 * 自定义ClientDetailsService，redis+jdbc方式加载客户端缓存
 * 继承JdbcClientDetailsService，扩展redis缓存加载客户端，优先从缓存获取客户端配置，缓存没有再从数据库加载
 */
@Service
public class RedisClientDetailsService extends JdbcClientDetailsService {

    public RedisClientDetailsService(DataSource dataSource) {
        super(dataSource);
    }





}
