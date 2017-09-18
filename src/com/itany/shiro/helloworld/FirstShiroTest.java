package com.itany.shiro.helloworld;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.*;
import org.apache.shiro.config.IniSecurityManagerFactory;
import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.session.Session;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.util.Factory;

public class FirstShiroTest {

    public static void main(String[] args) {

    	//初始化shiro.ini
        Factory<SecurityManager> factory = 
        		new IniSecurityManagerFactory("classpath:shiro.ini");
        //获取安全管理者实例
        SecurityManager securityManager = factory.getInstance();
        //设置安全管理者
        SecurityUtils.setSecurityManager(securityManager);

        // 获取当前的 Subject
        Subject currentUser = SecurityUtils.getSubject();

        // 测试使用 Session(即使不在web环境下也是可以的)
        // 获取 Session
        Session session = currentUser.getSession();
        session.setAttribute("username", "mike");
        String username = (String) session.getAttribute("username");
        if (username.equals("mike")) {
        	System.out.println("得到正确的值：" + username);
        }

        // 测试当前的用户是否已经被认证. 即是否已经登录. 
        if (!currentUser.isAuthenticated()) {
        	// 把用户名和密码封装为 UsernamePasswordToken 对象
            UsernamePasswordToken token = new UsernamePasswordToken("mike", "123");
            // rememberme
            token.setRememberMe(true);
            try {
            	//执行登录. 
                currentUser.login(token);
            } 
            //若没有指定的账户
            catch (UnknownAccountException uae) {
            	System.out.println("没有一个使用 【" + token.getPrincipal()+"】账号的用户");
                return; 
            } 
            //若账户存在,但密码不匹配 
            catch (IncorrectCredentialsException ice) {
            	System.out.println("【"+token.getPrincipal() + "】账号的密码不正确");
                return; 
            } 
            //用户被锁定的异常
            catch (LockedAccountException lae) {
            	System.out.println("用户名【"+token.getPrincipal()+"】的账号已被锁定，请联系你的管理员解锁");
            }
             //所有认证时异常的父类
            catch (AuthenticationException ae) {
            	System.out.println("未知情况");
            }
        }
        System.out.println("用户【" + currentUser.getPrincipal() + "】登陆成功");

        //测试是否有某一个角色
        if (currentUser.hasRole("a")) {
        	System.out.println("用户【" + currentUser.getPrincipal() + "】具有a权限");
        } else {
        	System.out.println("用户【" + currentUser.getPrincipal() + "】不具有a权限");
            return; 
        }
        //测试用户是否具备某一个行为. 调用 Subject 的 isPermitted() 方法。 
        if (currentUser.isPermitted("read:a")) {
        	System.out.println("你可以read a");
        } else {
        	System.out.println("你不可以read a");
        }
        // 执行登出
        System.out.println("【"+currentUser.getPrincipal()+"】是否被认证：" + currentUser.isAuthenticated());
        
        currentUser.logout();
        
        System.out.println("【"+currentUser.getPrincipal()+"】是否被认证：" + currentUser.isAuthenticated());

        System.exit(0);
    }
}
