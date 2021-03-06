package com.zjx.security.config;

import com.zjx.security.filter.TokenAuthFilter;
import com.zjx.security.filter.TokenLoginFilter;
import com.zjx.security.security.DefaultPasswordEncoder;
import com.zjx.security.security.TokenLogoutHandler;
import com.zjx.security.security.TokenManager;
import com.zjx.security.security.UnauthEntryPoint;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;

@Configuration
public class TokenWebSecurityConfig extends WebSecurityConfigurerAdapter{

    @Autowired
    private TokenManager tokenManager;

    @Autowired
    private RedisTemplate redisTemplate;

    @Autowired
    private DefaultPasswordEncoder defaultPasswordEncoder;

    @Autowired
    private UserDetailsService userDetailsService;


    //设置退出的地址和token,redis操作地址
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.exceptionHandling()
                .authenticationEntryPoint(new UnauthEntryPoint())//没有权限访问
                .and().csrf().disable()
                .authorizeRequests()
                .anyRequest().authenticated()
                .and().logout().logoutUrl("/admin/acl/index/logout") //退出路径
                .addLogoutHandler(new TokenLogoutHandler(tokenManager, redisTemplate)).and()
                .addFilter(new TokenLoginFilter(authenticationManager(), tokenManager, redisTemplate))
                .addFilter(new TokenAuthFilter(authenticationManager(), tokenManager, redisTemplate)).httpBasic();
    }

    //调用userDetailsService和密码处理
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(userDetailsService).passwordEncoder(defaultPasswordEncoder);
    }

    //不进行认证的路径
    @Override
    public void configure(WebSecurity web) throws Exception {
        web.ignoring().antMatchers("/api/**");
    }
}
