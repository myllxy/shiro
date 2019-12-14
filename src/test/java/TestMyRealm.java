import cn.myllxy.shiro.MyRealm;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.IncorrectCredentialsException;
import org.apache.shiro.authc.UnknownAccountException;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.authc.credential.HashedCredentialsMatcher;
import org.apache.shiro.mgt.DefaultSecurityManager;
import org.apache.shiro.subject.Subject;
import org.junit.Test;

/**
 * @author myllxy
 * @create 2019-12-14 12:30
 */
public class TestMyRealm {
    @Test
    public void testMyRealm() throws Exception {
        //一.创建一个SecurityManager对象
        // 1.创建realm对象
        MyRealm myRealm = new MyRealm();
        // 2.创建SecurityManager对象
        DefaultSecurityManager securityManager = new DefaultSecurityManager(myRealm);
        //②.相当于把SecurityManager放到了当前上下文
        SecurityUtils.setSecurityManager(securityManager);
        //③.拿到当前用户
        Subject subject = SecurityUtils.getSubject();

        //Hashed(哈希)Credentials(认证)Matcher(匹配器)
        HashedCredentialsMatcher matcher = new HashedCredentialsMatcher();
        //设置哈希算法
        matcher.setHashAlgorithmName("MD5");
        //设置迭代次数
        matcher.setHashIterations(10);
        //把匹配器交给shiro
        myRealm.setCredentialsMatcher(matcher);

        System.out.println("用户是否登录:" + subject.isAuthenticated());
        //④.如果没有登录，让他登录
        if (!subject.isAuthenticated()) {
            try {
                UsernamePasswordToken token = new UsernamePasswordToken("admin", "123456");
                subject.login(token);
            } catch (UnknownAccountException e) {
                e.printStackTrace();
                System.out.println("用户名错误");
            } catch (IncorrectCredentialsException e) {
                e.printStackTrace();
                System.out.println("密码错误");
            } catch (AuthenticationException e) {
                e.printStackTrace();
                System.out.println("神迷错误");
            }
        }
        System.out.println("用户是否登录:" + subject.isAuthenticated());

        System.out.println("是否是admin角色:" + subject.hasRole("admin"));
        System.out.println("是否是hr角色:" + subject.hasRole("hr"));

        System.out.println("是否有employee:index权限:" + subject.isPermitted("employee:index"));
        System.out.println("是否有employee:save权限:" + subject.isPermitted("employee:save"));
        System.out.println("是否有department:index权限:" + subject.isPermitted("department:index"));


    }
}
