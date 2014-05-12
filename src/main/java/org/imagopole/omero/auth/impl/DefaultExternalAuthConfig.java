/**
 *
 */
package org.imagopole.omero.auth.impl;

import java.util.Collections;
import java.util.List;
import java.util.Map;

import org.imagopole.omero.auth.api.ExternalAuthConfig;

/**
 * Default external auth config implementation, modeled after the existing {@link ome.security.auth.LdapConfig},
 * with the following differences:
 * - retains a subset of shared settings with the LDAP config (ie. <code>enabled</code> and
 *   <code>newUserGroup</code>).
 * - replaces <code>syncOnLogin</code> with two distinct settings to independently control the
 *   synchronization behaviour: only the user's groups and memberships, or only the user's
 *   attributes, or both.
 * - adds optional extra methods to allow filtering of user and group accounts - typically to
 *   exclude "protected" OMERO internal accounts (but not restricted to).
 * - adds optional extra methods to allow pre-seeding of LDAP-aware accounts - allows switching
 *   back to a LDAP-based PasswordProvider with no database migration.
 * - adds other settings with implicit use in {@link ome.security.auth.LdapConfig} but without
 *   configurable control (eg. strict mode for groups creation).
 * - adds a generic <code>configMap</code> to expose other implementation specific settings.
 *
 * @author seb
 *
 */
public class DefaultExternalAuthConfig implements ExternalAuthConfig {

    /** Should the authentication extension be activated in OMERO.server ?*/
    private final Boolean enabled;

    /** Group specifier as already in use by {@link ome.security.auth.LdapConfig} and {@link ome.logic.LdapImpl}.
     *  Only supports non-LDAP specific parameters, ie:
     *  literal group name and <code>:bean:<spring_bean_name></code> constructs. */
    private final String newUserGroup;

    /** Should the authentication extension perform groups and memberships synchronization upon login. */
    private final Boolean syncGroups;

    /** Should the authentication extension perform user attributes synchronization upon login. */
    private final Boolean syncUser;

    /** Additional implementation-specific configuration settings for management by the client. */
    private Map<String, Object> configMap;

    /**
     * Parameterized constructor.
     *
     * Groups and user synchronisation on login is disabled.
     *
     * @param enabled should the authentication extension be activated
     * @param newUserGroup group specifier as already in use by {@link ome.security.auth.LdapConfig}
     */
    public DefaultExternalAuthConfig(Boolean enabled, String newUserGroup) {
        this(enabled, newUserGroup, Boolean.FALSE, Boolean.FALSE, null);
    }

    /**
     * Full constructor.
     *
     * @param enabled should the authentication extension be activated
     * @param newUserGroup group specifier as already in use by {@link ome.security.auth.LdapConfig}
     * @param syncGroups should the authentication extension perform groups synchronization upon login
     * @param syncUser should the authentication extension perform user synchronization upon login
     * @param configMap additional implementation-specific configuration settings
     */
    @SuppressWarnings("unchecked")
    public DefaultExternalAuthConfig(
                    Boolean enabled,
                    String newUserGroup,
                    Boolean syncGroups,
                    Boolean syncUser,
                    Map<String, Object> configMap) {
        super();
        this.enabled = (null == enabled ? Boolean.FALSE : enabled);
        this.newUserGroup = ((null == newUserGroup || newUserGroup.trim().isEmpty()) ? null : newUserGroup.trim());
        this.syncGroups = (null == syncGroups ? Boolean.FALSE : syncGroups);
        this.syncUser = (null == syncUser ? Boolean.FALSE : syncUser);
        this.configMap = (null == configMap ? Collections.EMPTY_MAP : Collections.unmodifiableMap(configMap));
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public boolean isEnabled() {
        return this.enabled;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public String getNewUserGroup() {
        return this.newUserGroup;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    @SuppressWarnings("unchecked")
    public List<String> listExcludedGroups() {
        List<String> result = Collections.emptyList();

        if (null != getConfigMap() && getConfigMap().containsKey(ConfigKeys.EXCLUDE_GROUPS)) {
            result = (List<String>) getConfigMap().get(ConfigKeys.EXCLUDE_GROUPS);
        }

        return result;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    @SuppressWarnings("unchecked")
    public List<String> listExcludedUsers() {
        List<String> result = Collections.emptyList();

        if (null != getConfigMap() && getConfigMap().containsKey(ConfigKeys.EXCLUDE_USERS)) {
            result = (List<String>) getConfigMap().get(ConfigKeys.EXCLUDE_USERS);
        }

        return result;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public boolean failOnDuplicateGroups() {
        boolean result = false;

        if (null != getConfigMap() && getConfigMap().containsKey(ConfigKeys.FAIL_ON_DUPLICATE_GROUPS)) {
            String configValue = (String) getConfigMap().get(ConfigKeys.FAIL_ON_DUPLICATE_GROUPS);
            result =  Boolean.valueOf(configValue);
        }

        return result;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public boolean syncGroupsOnLogin() {
        return this.syncGroups;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public boolean syncUserOnLogin() {
        return this.syncUser;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Map<String, Object> getConfigMap() {
        return this.configMap;
    }

    /**
     * Keys for configuration settings defined in the application context.
     *
     * @see org.imagopole.omero.auth.impl.group.ConfigurableNameToGroupBean
     * @see ExternalConfigurablePasswordProvider
     */
    public class ConfigKeys {
        /** Common namespace for all settings related to external auth. */
        public static final String PREFIX                   = "omero.external_auth.";

        /** Protected group names to be filtered out of the external auth module's group bean. */
        public static final String EXCLUDE_GROUPS           = PREFIX + "groups.exclude_names";

        /** Protected user names to be filtered out of the external auth module's password provider. */
        public static final String EXCLUDE_USERS            = PREFIX + "users.exclude_names";

        /** Behaviour for group creation.
         *
         *  @see ome.security.auth.SimpleRoleProvider#createGroup(String, ome.model.internal.Permissions, boolean) */
        public static final String FAIL_ON_DUPLICATE_GROUPS = PREFIX + "groups.fail_duplicates";

        /** Constants class. */
        private ConfigKeys() {
            super();
        }
    }

    /**
     * Values for configuration settings defined in the application context.
     *
     * @see ome.model.internal.Permissions
     * @see org.imagopole.omero.auth.impl.group.ConfigurableNameToGroupBean
     */
    public class ConfigValues {
        /** Indicates that the group is <code>Private</code> i.e. RW----. */
        public static final String PRIVATE       = "private";

        /** Indicates that the group is <code>ReadOnly</code> i.e. RWR---. */
        public static final String READ_ONLY     = "read-only";

        /** Indicates that the group is <code>ReadAnnotate</code> i.e. RWRA--. */
        public static final String READ_ANNOTATE = "read-annotate";

        /** Constants class. */
        private ConfigValues() {
            super();
        }
    }

}
