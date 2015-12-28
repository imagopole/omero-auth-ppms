/**
 *
 */
package org.imagopole.omero.auth.impl.group;


import java.util.List;

import org.imagopole.omero.auth.api.ExternalAuthConfig;
import org.imagopole.omero.auth.api.dto.NamedItem;
import org.imagopole.omero.auth.impl.DefaultExternalAuthConfig;
import org.imagopole.omero.auth.util.ConvertUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * A {@link ome.security.auth.NewUserGroupBean} implementation which allows a CSV list of group
 * names to be specified (similar to LdapImpl behaviour, only with support for multiple values).
 *
 * Group names exclusions are applied, so any name clash will result in the name being skipped.
 *
 * @author seb
 */
public class ListToGroupsBean extends ConfigurableNameToGroupBean {

    /** Application logs. */
    private final Logger log = LoggerFactory.getLogger(ListToGroupsBean.class);

    /** Configurable permission level enumeration for use at group creation time.
     *
     *  @see org.imagopole.omero.auth.impl.DefaultExternalAuthConfig.ConfigValues */
    private String permissionLevel;

    public ListToGroupsBean() {
        super();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    protected boolean isEnabled() {
        // since this GroupBean implementation does not rely on a remote endpoint's availability,
        // allow to be configured and executed regardless of the external auth config flag
        return true;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    protected List<NamedItem> listItemsByUserName(String username, ExternalAuthConfig config) {
        log.debug("[external_auth ] looking up configured group names for username: {}", username);

        List<String> groupNames = ConvertUtil.lookupCsvValue(config, CsvListConfigKeys.CSV_GROUPS_LIST);

        return ConvertUtil.toSimpleNamedItems(groupNames);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    protected String getPermissionLevel() {
        return this.permissionLevel;
    }

    /**
     * Sets permissionLevel.
     * @param permissionLevel the permissionLevel to set
     */
    public void setPermissionLevel(String permissionLevel) {
        this.permissionLevel = permissionLevel;
    }

    /**
     * Keys for configuration settings defined in the application context.
     *
     * @see ConfigurableNameToGroupBean
     * @see org.imagopole.omero.auth.impl.ExternalConfigurablePasswordProvider
     */
    public class CsvListConfigKeys {
        /** Common namespace for all settings related to external auth. */
        public static final String PREFIX          = DefaultExternalAuthConfig.ConfigKeys.PREFIX;

        /** CSV string with a list of predefined group names. */
        public static final String CSV_GROUPS_LIST = PREFIX + "groups.csv_list";

        /** Constants class. */
        private CsvListConfigKeys() {
            super();
        }
    }

}
