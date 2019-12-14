package cn.myllxy.shiro;


import org.apache.shiro.authc.*;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.util.ByteSource;

import java.util.HashSet;
import java.util.Set;

/**
 * @author myllxy
 * @create 2019-12-14 11:02
 */
public class MyRealm extends AuthorizingRealm {

    //授权认证功能就写在这里面
    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principalCollection) {
        SimpleAuthorizationInfo authorizationInfo = new SimpleAuthorizationInfo();
        //从数据库中获取角色并放且放到授权对象中
        Set<String> roles = getRoles();
        authorizationInfo.setRoles(roles);
        //从数据库中获取权限并放且放到授权对象中
        Set<String> perms = getPerms();
        authorizationInfo.setStringPermissions(perms);
        return authorizationInfo;
    }

    /**
     * 假设这里获取到当前用户的角色
     */
    private Set<String> getRoles() {
        Set<String> roles = new HashSet<String>();
        roles.add("admin");
        roles.add("it");
        return roles;
    }

    /**
     * 假设这里获取到当前用户的权限
     */
    private Set<String> getPerms() {
        Set<String> perms = new HashSet<String>();
        perms.add("employee:index");
        return perms;
    }

    /**
     * 记住：如果这个方法返回null,就代表是用户名错误，shiro就会抛出:UnknownAccountException
     */
    //身份认证(登录)就写在这里面
    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken authenticationToken) throws AuthenticationException {
        //1.拿到令牌(UsernamePasswordToken)
        UsernamePasswordToken token = (UsernamePasswordToken) authenticationToken;
        //2.拿到用户名，判断这个用户是否存在
        // 2.1 拿到传过来的用户名
        String username = token.getUsername();
        // 2.2 根据用户名从数据库中拿到密码(以后会拿用户对象)
        String password = this.getUsers(username);
        // 2.3 如果没有拿到密码(没有通过用户名拿到相应的用户->用户不存在)
        if (password == null) {
            return null;
        }

        //记住：我们只在正常完成这里的功能，shiro会判断密码是否正确
        //3.返回 AuthenticationInfo这个对象
        /**
         * 咱们创建对象需要传的参数:
         * Object principal:主体(可以乱写) -> 登录成功后，你想把哪一个对象存下来
         * Object credentials：凭证(就是密码) -> 数据库中的密码
         * credentials(密码)Salt:盐值
         * String realmName : realm的名称(可以乱写)
         */
        //拿到咱们的盐值对象(ByteSource)
        ByteSource salt = ByteSource.Util.bytes("itsource");
        SimpleAuthenticationInfo authenticationInfo = new SimpleAuthenticationInfo(username, password, salt, "myRealm");
        return authenticationInfo;
    }

    /**
     * 假设这里是根据用户名进行的查询
     * MD5:e10adc3949ba59abbe56e057f20f883e
     * MD5+10次:4a95737b032e98a50c056c41f2fa9ec6
     * MD5+10次+itsource:831d092d59f6e305ebcfa77e05135eac
     */
    public String getUsers(String username) {
        if ("admin".equals(username)) {
            return "831d092d59f6e305ebcfa77e05135eac";
        } else if ("zhang".equals(username)) {
            return "123";
        }
        return null;
    }
}