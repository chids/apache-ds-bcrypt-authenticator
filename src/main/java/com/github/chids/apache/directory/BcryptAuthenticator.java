package com.github.chids.apache.directory;

import static org.apache.directory.shared.ldap.model.constants.SchemaConstants.USER_PASSWORD_AT;

import org.apache.directory.server.core.api.LdapPrincipal;
import org.apache.directory.server.core.api.interceptor.context.BindOperationContext;
import org.apache.directory.server.core.authn.AbstractAuthenticator;
import org.apache.directory.server.i18n.I18n;
import org.apache.directory.shared.ldap.model.constants.AuthenticationLevel;
import org.apache.directory.shared.ldap.model.entry.Entry;
import org.apache.directory.shared.ldap.model.exception.LdapAuthenticationException;
import org.apache.directory.shared.ldap.model.name.Dn;
import org.mindrot.jbcrypt.BCrypt;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class BcryptAuthenticator extends AbstractAuthenticator {

    private static final Logger LOG = LoggerFactory.getLogger(BcryptAuthenticator.class);

    public BcryptAuthenticator() {
        super(AuthenticationLevel.SIMPLE);
    }

    @Override
    public LdapPrincipal authenticate(BindOperationContext ctx) throws Exception {
        final Dn dn = ctx.getDn();
        if(LOG.isDebugEnabled()) {
            LOG.debug("About to authenticate: " + dn);
        }
        final Entry entry = ctx.getEntry();
        if(entry.containsAttribute(USER_PASSWORD_AT)) {
            final String actual = new String(entry.get(USER_PASSWORD_AT).getBytes());
            final String candidate = new String(ctx.getCredentials());
            if(BCrypt.checkpw(candidate, actual)) {
                return new LdapPrincipal(
                        super.getDirectoryService().getSchemaManager(),
                        dn,
                        AuthenticationLevel.SIMPLE);
            }
        }
        else if(LOG.isWarnEnabled()) {
            LOG.warn("No password attribute present for: " + dn);
        }
        throw new LdapAuthenticationException(I18n.err(I18n.ERR_230, dn.getName()));
    }
}