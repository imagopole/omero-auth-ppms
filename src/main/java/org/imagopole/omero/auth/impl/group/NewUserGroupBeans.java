/**
 *
 */
package org.imagopole.omero.auth.impl.group;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

import ome.security.auth.AttributeSet;
import ome.security.auth.LdapConfig;
import ome.security.auth.NewUserGroupBean;
import ome.security.auth.RoleProvider;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.ldap.core.LdapOperations;

/**
 * Composite class which delegates to each of the configured {@link NewUserGroupBean} in turn.
 *
 * Accumulates all group identifiers (excluding duplicates) to allow for multiple external role
 * sources to be combined.
 *
 * Follows a chaining approach similar to {@link ome.security.auth.PasswordProviders}.
 *
 * @author seb
 *
 */
public class NewUserGroupBeans implements NewUserGroupBean {

    /** Application logs. */
    private final Logger log = LoggerFactory.getLogger(NewUserGroupBeans.class);

    /** The @link {@link NewUserGroupBean}s sequence to invoke. */
    private final List<NewUserGroupBean> groupBeans;

    /**
     * Parameterized constructor.
     * @param groupBeans the group replication beans
     */
    @SuppressWarnings("unchecked")
    public NewUserGroupBeans(List<NewUserGroupBean> groupBeans) {
        super();
        this.groupBeans = (null == groupBeans ? Collections.EMPTY_LIST : groupBeans);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public List<Long> groups(
                    String username,
                    LdapConfig config,
                    LdapOperations ldap,
                    RoleProvider provider,
                    AttributeSet attrSet) {

        Set<Long> allGroups = new LinkedHashSet<Long>();

        for (NewUserGroupBean bean : groupBeans) {
            log.debug("[external_auth] Invoking chained newUserGroupBean: {}", bean);
            List<Long> groups = bean.groups(username, config, ldap, provider, attrSet);

            if (null != groups && !groups.isEmpty()) {

                log.debug("[external_auth] Retrieved: {} group(s)", groups.size());
                allGroups.addAll(groups);

            }
        }

        return new ArrayList<Long>(allGroups);
    }

}
