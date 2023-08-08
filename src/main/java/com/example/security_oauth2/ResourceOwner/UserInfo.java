package com.example.security_oauth2.ResourceOwner;

import lombok.Data;

/**
 * 搭建Web安全配置
 * 第一步
 * 资源所有者（ResourceOwner）信息准备
 * 资源所有者就是用户，因此我们同样用java对象的方式构建一个用户信息。注意后续应该从数据库读取。
 */
@Data
public class UserInfo {
	/**登录用户名*/
	private String userName = "hutao";
	/**登录密码*/
	private String passWord = "123456";
	/**用户权限*/
	private String role = "admin";
}
