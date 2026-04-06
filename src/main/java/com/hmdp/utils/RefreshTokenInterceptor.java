package com.hmdp.utils;

import cn.hutool.core.bean.BeanUtil;
import cn.hutool.core.util.StrUtil;
import com.hmdp.dto.UserDTO;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.web.servlet.HandlerInterceptor;

import javax.annotation.Resource;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Map;
import java.util.concurrent.TimeUnit;

public class RefreshTokenInterceptor implements HandlerInterceptor {
    //这里并不是自动装配，因为RefreshTokenInterceptor是我们手动在WebConfig里new出来的
    private StringRedisTemplate stringRedisTemplate;

    public RefreshTokenInterceptor(StringRedisTemplate stringRedisTemplate) {
        this.stringRedisTemplate = stringRedisTemplate;
    }

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception {
        // 1. 获取请求头中的token
        String token = request.getHeader("authorization");
        // 2. 如果token是空，直接放行，交给LoginInterceptor处理
        if (StrUtil.isBlank(token)) {
            return true;
        }

        // 3. 校验JWT有效性（签名和过期时间）
        if (!JwtUtils.validateToken(token)) {
            return true;
        }

        // 4. 解析JWT获取用户ID
        Object userIdObj = JwtUtils.parseToken(token).getPayload("id");
        if (userIdObj == null) {
            return true;
        }
        Long userId = Long.valueOf(userIdObj.toString());

        // 5. 基于用户ID从Redis获取数据
        String key = RedisConstants.LOGIN_USER_KEY + userId;
        Map<Object, Object> userMap = stringRedisTemplate.opsForHash().entries(key);

        // 6. 判断用户是否存在
        if (userMap.isEmpty()) {
            return true;
        }

        // 7. 校验Token一致性（防止旧Token登录，实现单端登录逻辑）
        String cachedToken = (String) userMap.get("token");
        if (!token.equals(cachedToken)) {
            return true;
        }

        // 8. 将查询到的Hash数据转化为UserDto对象
        UserDTO userDTO = BeanUtil.fillBeanWithMap(userMap, new UserDTO(), false);

        // 9. 将用户信息保存到ThreadLocal
        UserHolder.saveUser(userDTO);

        // 10. 刷新tokenTTL
        stringRedisTemplate.expire(key, RedisConstants.LOGIN_USER_TTL, TimeUnit.MINUTES);
        return true;
    }

    @Override
    public void afterCompletion(HttpServletRequest request, HttpServletResponse response, Object handler, Exception ex) throws Exception {
        //移除threadlocal用户，避免内存泄漏
        UserHolder.removeUser();
    }
}
