package com.example.security_oauth2.AuthorizationServer;

import lombok.Data;

/**
 * 搭建授权服务器  定义授权服务器，用注解@EnableAuthorizationServer；
 * 第一步
 * 客户端应用（client）信息准备
 * 在这里我们暂时使用java对象的方式构建了一个客户端信息。注意，后续这块数据应该从数据库读取
 */
@Data
public class ClientInfo {
	/**客户端ID*/
    private String clientId = "client_hutao";
    /**客户端秘钥*/
    private String clientSecret = "secret_hutao";
    /**授权范围*/
    private String scop = "all";
    /**token有效期*/
    private int tokenValid = 60*30*4;
    /**flush_token有效期*/
    private int flushTokenValid = 60*30*4;
    /**授权模式:授权码模式，简化模式，密码模式，客户端模式*/
    private String [] grantTypes= {"authorization_code","implicit","password","client_credentials"};
}
