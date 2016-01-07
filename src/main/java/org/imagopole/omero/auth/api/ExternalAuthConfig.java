/**
 *
 */
package org.imagopole.omero.auth.api;

import java.util.List;
import java.util.Map;

/**
 * Configuration holder for an external OMERO authentication extension.
 *
 * Modeled after the existing {@link ome.security.auth.LdapConfig}, with the following differences:
 * - retains a subset of shared settings with the LDAP config (ie. <code>enabled</code> and
 *   <code>newUserGroup</code>).
 * - replaces <code>syncOnLogin</code> with two distinct settings to independently control the
 *   synchronization behaviour: only the user's groups and memberships, or only the user's
 *   attributes, or both.
 * - adds extra methods to allow filtering of user and group accounts - typically to
 *   exclude "protected" OMERO internal accounts (but not restricted to).
 * - adds other settings with implicit use in {@link ome.security.auth.LdapConfig} but without
 *   configurable control (eg. strict mode for groups creation)
 * - adds a generic <code>configMap</code> to expose other implementation specific settings.
 *
 * @author seb
 *
 */
public interface ExternalAuthConfig {

    /** Should the authentication extension be activated in OMERO.server? */
    boolean isEnabled();

    /** Group specifier as already in use by {@link ome.security.auth.LdapConfig} and {@link ome.logic.LdapImpl}.
     *  Only supports non-LDAP specific parameters, ie:
     *  literal group name and <code>:bean:<spring_bean_name></code> constructs.
     *  @see ome.security.auth.LdapConfig#getNewUserGroup() */
    String getNewUserGroup();

    /**
     * Group specifier for default group overriding at user profile synchronization time.
     * Only supports literal group name and <code>:bean:<spring_bean_name></code> constructs.
     * @see #getNewUserGroup()
     */
    String getDefaultGroup();

    /**
     * Regular expression for conditional default group overriding - default group name
     * shall be synchronized only if it matches the configured pattern.
     */
    String getDefaultGroupPattern();

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
     * @see ome.security.auth.SimpleRoleProvider#createGroup(String, ome.model.internal.Permissions, boolean)
     */
    boolean failOnDuplicateGroups();

    /**
     * Indicates whether the groups and memberships for this user should be synchronized upon login.
     * @see ome.security.auth.LdapConfig#isSyncOnLogin() */
    boolean syncGroupsOnLogin();

    /**
     * Indicates whether the default group for this user should be synchronized upon login.
     */
    boolean syncDefaultGroupOnLogin();

    /**
     * Indicates whether the attributes (first name, last name, email, etc.) for this user should
     * be synchronized upon login.
     * @see ome.security.auth.LdapConfig#isSyncOnLogin() */
    boolean syncUserOnLogin();

    /** Additional implementation-specific configuration settings for management by the client. */
    Map<String, Object> getConfigMap();

}
