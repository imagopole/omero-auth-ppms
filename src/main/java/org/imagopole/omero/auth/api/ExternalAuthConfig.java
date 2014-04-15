/**
 *
 */
package org.imagopole.omero.auth.api;

import java.util.List;
import java.util.Map;

import ome.logic.LdapImpl;
import ome.security.auth.LdapConfig;
import ome.security.auth.SimpleRoleProvider;

/**
 * Configuration holder for an external OMERO authentication extension.
 *
 * Modeled after the existing {@link LdapConfig}, with the following differences:
 * - retains a subset of shared settings with the LDAP config (ie. <code>enabled</code>,
 *   <code>syncOnLogin</code> and <code>newUserGroup</code>)
 * - adds extra methods to allow filtering of user and group accounts - typically to
 *   exclude "protected" OMERO internal accounts (but not restricted to).
 * - adds other settings with implicit use in {@link LdapConfig} but without configurable
 *   control (eg. strict mode for groups creation)
 * - adds a generic <code>configMap</code> to expose other implementation specific settings.
 *
 * @author seb
 *
 */
public interface ExternalAuthConfig {

    /** Should the authentication extension be activated in OMERO.server? */
    boolean isEnabled();

    /** Should the authentication extension perform user and groups synchronization upon login? */
    boolean isSyncOnLogin();

    /** Group specifier as already in use by {@link LdapConfig} and {@link LdapImpl}.
     *  Only supports non-LDAP specific parameters, ie:
     *  literal group name and <code>:bean:<spring_bean_name></code> constructs. */
    String getNewUserGroup();

   /**
    * Returns the list of group names to be filtered out from the external to OMERO synchronization, if any.
    * @return empty list if no group exclusions were configured.
    */
    List<String> listExcludedGroups();

    /**
     * Returns the list of user names to be filtered out from the external to OMERO synchronization, if any.
     * @return empty list if no user exclusions were configured.
     */
    List<String> listExcludedUsers();

    /**
     * Indicates whether "strict" group creation mode should be used.
     * @see SimpleRoleProvider#createGroup(String, ome.model.internal.Permissions, boolean)
     */
    boolean failOnDuplicateGroups();

    /** Additional implementation-specific configuration settings for management by the client. */
    Map<String, Object> getConfigMap();

}
