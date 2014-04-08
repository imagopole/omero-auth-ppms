/**
 *
 */
package org.imagopole.omero.auth.impl.group;

import java.util.List;

import ome.security.auth.AttributeSet;
import ome.security.auth.LdapConfig;
import ome.security.auth.LdapPasswordProvider;
import ome.security.auth.NewUserGroupBean;
import ome.security.auth.OrgUnitNewUserGroupBean;
import ome.security.auth.RoleProvider;
import ome.security.auth.SimpleRoleProvider;
import ome.security.auth.providers.LdapPasswordProvider431;

import org.imagopole.omero.auth.api.ExternalAuthConfig;
import org.imagopole.omero.auth.api.group.ExternalNewUserGroupBean;
import org.imagopole.omero.auth.util.Check;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.ldap.core.LdapOperations;

/**
 * A simple adapter to map OMERO's {@link NewUserGroupBean} LDAP-oriented API
 * to the {@link ExternalNewUserGroupBean}.
 *
 * This allows {@link ExternalNewUserGroupBean} implementations to be used together with some of
 * OMERO's LDAP password providers such as {@link LdapPasswordProvider} and {@link LdapPasswordProvider431}.
 * This would typically be used to let the LDAP be the authentication source, while fetching
 * roles/groups from an external source.
 *
 * @author seb
 *
 */
public abstract class NewUserGroupBeanAdapter implements NewUserGroupBean, ExternalNewUserGroupBean {

    /** Application logs */
    private final Logger log = LoggerFactory.getLogger(NewUserGroupBeanAdapter.class);

    /** External configuration holder. */
    private ExternalAuthConfig externalConfig;

    /**
     * Adapts the {@link NewUserGroupBean} group retrieval method to
     * the {@link ExternalNewUserGroupBean} API.
     *
     * Subclasses must be mindful that configuration settings may be null in this context: the
     * {@link ExternalAuthConfig} is looked up from the Spring application context, and may or not
     * be present.
     *
     * Like {@link OrgUnitNewUserGroupBean} and friends, the implementation may create
     * the OMERO group.
     *
     * @see SimpleRoleProvider#createGroup(String, ome.model.internal.Permissions, boolean)
     */
    @Override
    public List<Long> groups(
                    String username,
                    LdapConfig config,
                    LdapOperations ldap,
                    RoleProvider provider,
                    AttributeSet attrSet) {

        Check.notEmpty(username, "username");
        Check.notNull(provider, "roleProvider");

        log.debug("[external_auth] Adapting NewUserGroupBean with externalConfig: {}", getExternalConfig());
        return groups(username, getExternalConfig(), provider);
    }

    /**
     * Returns externalConfig.
     * @return the externalConfig
     */
    public ExternalAuthConfig getExternalConfig() {
        return externalConfig;
    }

    /**
     * Sets externalConfig.
     * @param externalConfig the externalConfig to set
     */
    public void setExternalConfig(ExternalAuthConfig externalConfig) {
        this.externalConfig = externalConfig;
    }

}
