import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.IncorrectCredentialsException;
import org.apache.shiro.authc.UnknownAccountException;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.config.IniSecurityManagerFactory;
import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.util.Factory;
import org.junit.Test;

/**
 * @author myllxy
 * @create 2019-12-14 7:25
 */
public class TestShiro {
    @Test
    public void testHello() throws Exception {
        //①.拿到权限管理对象
        /*
         * 读取了shiro.ini的文件(隐藏了realm) -> 隐藏了iniRealm
         * SecurityManager:权限管理器，shiro的所有功能都放在里面
         */
        Factory<SecurityManager> factory = new IniSecurityManagerFactory("classpath:shiro.ini");
        SecurityManager securityManager = factory.getInstance();
        //②.相当于把SecurityManager放到了当前上下文
        /*
         * 可以让我们在当前系统的任何位置都可以拿到SecurityManager对象
         */
        SecurityUtils.setSecurityManager(securityManager);
        //③.拿到当前用户(没有登录就是游客)
        Subject currentUser = SecurityUtils.getSubject();
        System.out.println("用户是否登录：" + currentUser.isAuthenticated());

        //④.如果没有登录，让他进行登录
        if (!currentUser.isAuthenticated()) {
            try {
                //4.1 准备令牌(对象) 用户名密码令牌
                UsernamePasswordToken token = new UsernamePasswordToken("guest", "guest");
                //4.2 进行登录功能
                currentUser.login(token);
                System.out.println("当前用户是否有hr角色" + currentUser.hasRole("hr"));
                System.out.println("当前用户是否有employee权限" + currentUser.isPermitted("employee:save"));
            } catch (UnknownAccountException e) {
                //Unknown(未知)Account(账号)Exception:用户名不存在
                e.printStackTrace();
                System.out.println("账号错误");
            } catch (IncorrectCredentialsException e) {
                //Incorrect(不正确)Credentials(凭证)Exception:密码错误
                e.printStackTrace();
                System.out.println("密码错误");
            } catch (AuthenticationException e) {
                //AuthenticationException:登录中最大的那个异常
                e.printStackTrace();
                System.out.println("发生了一个神秘的错误！！！");
            }
        }
        System.out.println("==============================");
        System.out.println("用户是否登录：" + currentUser.isAuthenticated());
        System.out.println("是否是管理员角色：" + currentUser.hasRole("admin"));
        System.out.println("是否是IT角色：" + currentUser.hasRole("it"));
        System.out.println("是否可以操作employee:save权限:" + currentUser.isPermitted("employee:save"));
        System.out.println("是否可以操作employee:index权限:" + currentUser.isPermitted("employee:index"));
        System.out.println("是否可以操作department:index权限:" + currentUser.isPermitted("department:index"));
        //⑤.还可以登出(注销)
        currentUser.logout();
        System.out.println("用户是否登录：" + currentUser.isAuthenticated());
    }
}
