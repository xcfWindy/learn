package com.example.security_oauth2.TokenStoreConfig;

import cn.hutool.core.util.IdUtil;
import cn.hutool.core.util.ObjectUtil;
import org.springframework.security.oauth2.common.util.OAuth2Utils;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.OAuth2Request;
import org.springframework.security.oauth2.provider.token.DefaultAuthenticationKeyGenerator;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.TreeSet;

/**
 * 自定义类继承DefaultAuthenticationKeyGenerator进行扩展
 * 需要是根据不同的认证方式产生不同的token,所以只需要让生成token的key值不同即可,既生成key的Map不同
 * 所以只重写extractKey方法
 */
public class MyAuthenticationKeyGenerator extends DefaultAuthenticationKeyGenerator {

    private static final String CLIENT_ID = "client_id";

    private static final String SCOPE = "scope";

    private static final String USERNAME = "username";

    private static final String GRANTTYPE = "grant_type";

    public String extractKey(OAuth2Authentication authentication) {
        Map<String, String> values = new LinkedHashMap<String, String>();
        OAuth2Request authorizationRequest = authentication.getOAuth2Request();
        if (!authentication.isClientOnly()) {
            values.put(USERNAME, authentication.getName());
        }

        //将认证类型grant_type加入到Map中
        String grant_type = authorizationRequest.getRequestParameters().get(GRANTTYPE);

        if (!ObjectUtil.isEmpty(grant_type)){
            values.put(GRANTTYPE, grant_type);
        }

        values.put(CLIENT_ID, authorizationRequest.getClientId());

        if (authorizationRequest.getScope() != null) {
            values.put(SCOPE, OAuth2Utils.formatParameterList(new TreeSet<String>(authorizationRequest.getScope())));
        }

        //如果要实现每次登录token都不同可加入uuid
        //String uuid = IdUtil.simpleUUID();
        //values.put("code", uuid);

        return generateKey(values);
    }
}
