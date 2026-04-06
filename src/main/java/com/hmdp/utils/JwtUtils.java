package com.hmdp.utils;

import cn.hutool.jwt.JWT;
import cn.hutool.jwt.JWTUtil;
import java.nio.charset.StandardCharsets;
import java.util.Map;

public class JwtUtils {
    // 秘钥，实际开发中建议放在配置文件中
    private static final byte[] DEFAULT_KEY = "hmdp-auth-secret-key-1234567890".getBytes(StandardCharsets.UTF_8);

    /**
     * 创建令牌
     *
     * @param payloads 载荷
     * @param key      秘钥
     * @return 令牌
     */
    public static String createToken(Map<String, Object> payloads) {
        return JWTUtil.createToken(payloads, DEFAULT_KEY);
    }

    /**
     * 解析令牌
     *
     * @param token 令牌
     * @return JWT对象
     */
    public static JWT parseToken(String token) {
        return JWTUtil.parseToken(token);
    }

    /**
     * 校验令牌有效性（签名和过期时间）
     *
     * @param token 令牌
     * @return 是否有效
     */
    public static boolean validateToken(String token) {
        try {
            return JWTUtil.verify(token, DEFAULT_KEY);
        } catch (Exception e) {
            return false;
        }
    }
}
