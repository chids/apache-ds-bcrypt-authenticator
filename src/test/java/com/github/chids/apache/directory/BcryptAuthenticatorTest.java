package com.github.chids.apache.directory;

import org.apache.commons.lang.StringUtils;
import org.apache.directory.server.core.annotations.CreateAuthenticator;
import org.apache.directory.server.core.annotations.CreateDS;
import org.apache.directory.server.core.api.DirectoryService;
import org.apache.directory.server.core.api.interceptor.Interceptor;
import org.apache.directory.server.core.authn.AuthenticationInterceptor;
import org.apache.directory.server.core.factory.DSAnnotationProcessor;
import org.apache.directory.shared.ldap.model.exception.LdapAuthenticationException;
import org.apache.directory.shared.ldap.model.exception.LdapException;
import org.apache.directory.shared.ldap.model.name.Dn;
import org.junit.Before;
import org.junit.Test;
import org.mindrot.jbcrypt.BCrypt;

@CreateDS(
        // This authenticator is never added to the DirectoryService due to the bug
        // handled by parryForBugInDSAnnotationProcessor() below
        // see: https://issues.apache.org/jira/browse/DIRSERVER-1730
        authenticators = { @CreateAuthenticator(type = BcryptAuthenticator.class) })
public class BcryptAuthenticatorTest {

    private static final String CN = "bcrypt-password-user";
    private static final String USER_DN = "cn=" + CN + ",ou=system";
    private static final String PASSWORD = "fuuu";
    private static final String PASSWORD_HASH = BCrypt.hashpw(PASSWORD, BCrypt.gensalt());

    private DirectoryService ds;

    @Before
    public void initService() throws Exception {
        this.ds = DSAnnotationProcessor.getDirectoryService();
        DSAnnotationProcessor.injectEntries(this.ds, "dn: " + USER_DN + "\n" +
                "objectClass: person\n" +
                "cn: " + CN + "\n" +
                "sn: " + CN + "_test\n" +
                "userPassword: " + PASSWORD_HASH + "\n\n");
        parryBugInDSAnnotationProcessor(this.ds);
    }

    public void stopService() throws Exception {
        this.ds.shutdown();
    }

    @Test
    public void authenticationSuccess() throws Exception {
        this.ds.getSession(new Dn(USER_DN), PASSWORD.getBytes());
    }

    @Test(expected = LdapAuthenticationException.class)
    public void authenticationFailure() throws Exception {
        this.ds.getSession(new Dn(USER_DN), StringUtils.reverse(PASSWORD).getBytes());
    }

    private static void parryBugInDSAnnotationProcessor(DirectoryService ds) throws LdapException {
        final AuthenticationInterceptor interceptor = findAuthInterceptor(ds);
        interceptor.getAuthenticators().add(new BcryptAuthenticator());
        interceptor.init(ds);
    }

    private static AuthenticationInterceptor findAuthInterceptor(DirectoryService ds) {
        for(Interceptor interceptor : ds.getInterceptors()) {
            if(interceptor instanceof AuthenticationInterceptor) {
                return (AuthenticationInterceptor)interceptor;
            }
        }
        return null;
    }
}
