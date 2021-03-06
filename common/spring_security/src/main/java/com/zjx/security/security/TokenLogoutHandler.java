package com.zjx.security.security;

import com.zjx.utils.utils.R;
import com.zjx.utils.utils.ResponseUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.LogoutHandler;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

//退出处理器
public class TokenLogoutHandler implements LogoutHandler{

//    @Autowired
    private TokenManager tokenManager;

//    @Autowired
    private RedisTemplate redisTemplate;

    public TokenLogoutHandler(TokenManager tokenManager, RedisTemplate redisTemplate) {
        this.tokenManager = tokenManager;
        this.redisTemplate = redisTemplate;
    }

    @Override
    public void logout(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, Authentication authentication) {
        //1.从header里面获取token
        //2.token不为空，移除token,从redis删除token
        String token = httpServletRequest.getHeader("token");
        if (token != null){
            //移除
            tokenManager.removeToken(token);
            //从token获取用户名
            String username = tokenManager.getUserInfoFromToken(token);
            redisTemplate.delete(username);
            ResponseUtil.out(httpServletResponse, R.ok());
        }
    }
}
