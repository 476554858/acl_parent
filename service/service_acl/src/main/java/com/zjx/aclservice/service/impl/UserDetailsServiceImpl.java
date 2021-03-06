package com.zjx.aclservice.service.impl;

import com.zjx.aclservice.entity.User;
import com.zjx.aclservice.service.PermissionService;
import com.zjx.aclservice.service.UserService;
import com.zjx.security.entity.SecurityUser;
import org.springframework.beans.BeanUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.List;

@Service("userDetailsService")
public class UserDetailsServiceImpl implements UserDetailsService {

    @Autowired
    private UserService userService;

    @Autowired
    private PermissionService permissionService;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        //根据用户名查询数据
        User user = userService.selectByUsername(username);
//        //判断
        if(user == null) {
            throw new UsernameNotFoundException("用户不存在");
        }
        com.zjx.security.entity.User curUser = new com.zjx.security.entity.User();

        BeanUtils.copyProperties(user,curUser);
//
//        //根据用户查询用户权限列表
        List<String> permissionValueList = permissionService.selectPermissionValueByUserId(user.getId());
        SecurityUser securityUser = new SecurityUser();
        securityUser.setCurrentUserInfo(curUser);
        securityUser.setPermissionValueList(permissionValueList);
        return securityUser;
    }
}
