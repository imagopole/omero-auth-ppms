/**
 *
 */
package org.imagopole.omero.auth.impl.group;

import java.util.ArrayList;
import java.util.List;

import ome.model.internal.Permissions;
import ome.security.auth.NewUserGroupBean;
import ome.security.auth.RoleProvider;

import org.imagopole.omero.auth.api.ExternalAuthConfig;
import org.imagopole.omero.auth.api.dto.NamedItem;
import org.imagopole.omero.auth.impl.DefaultExternalAuthConfig.ConfigValues;
import org.imagopole.omero.auth.util.Check;
import org.imagopole.omero.auth.util.ConvertUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A {@link NewUserGroupBean} implementation which provides additional configuration settings:
 * - a permission level to be applied to the created groups (currently supports private, read-only
 * and read-annotate)
 * - filtering of group names (currently the default list excludes OMERO system groups: system, guest, user, default)
 *
 * @author seb
 *
 * @see ConfigValues
 */
public abstract class ConfigurableNameToGroupBean extends NewUserGroupBeanAdapter {

    /** Application logs */
    private final Logger log = LoggerFactory.getLogger(ConfigurableNameToGroupBean.class);

    /**
     * Template method for the retrieval of item names to be converted to OMERO groups for
     * a given OMERO user.
     *
     * @param username the OMERO user.
     * @param config the external configuration holder
     * @return the created OMERO model entities for groups the user is a member of.
     */
    protected abstract List<NamedItem> listItemsByUserName(String username, ExternalAuthConfig config);

    /**
     * A configured string value to assign the group-level permissions upon creation
     * of the OMERO group.
     *
     * May return null - if so, the group will be considered private.
     * Supported configuration values are: private | read_only | read_annotate
     *
     * @return null to indicate a private group, or one of private | read_only | read_annotate
     * @see ConfigValues
     */
    protected abstract String getPermissionLevel();

    /**
     * {@inheritDoc}
     */
    @Override
    public List<Long> groups(String username, ExternalAuthConfig config, RoleProvider provider) {
        Check.notEmpty(username, "username");
        Check.notNull(config, "authConfig");
        Check.notNull(provider, "roleProvider");

        List<Long> result = new ArrayList<Long>();

        // let the subclass retrieve the group names from the appropriate data source
        List<NamedItem> items = listItemsByUserName(username, config);

        // take care of the item name to OMERO group mapping, filtering and creation
        if (null != items && !items.isEmpty()) {

            boolean strictModeOn = config.failOnDuplicateGroups();

            // let subclasses define the permission level for various group mapping policies
            Permissions groupPermissions = ConvertUtil.toPermissionsOrNull(getPermissionLevel());

            for (NamedItem item : items) {
                String groupName = item.getName();

                // note: could be interesting to retrieve extra external info here
//                ExternalInfo externalInfo = new ExternalInfo();
//                externalInfo.setEntityType(item.getType()); // eg. "/ppms/system", "/ppms/project",
//                                                            // or xxx.class.getName(), or configurable token
//                externalInfo.setEntityId(item.getExternalId());
//
//                ExperimenterGroup groupWithDetails = new ExperimenterGroup();
//                groupWithDetails.setName(groupName);
//                groupWithDetails.getDetails().setPermissions(groupPermissions);
//                groupWithDetails.getDetails().setExternalInfo(externalInfo);
//                // then call provider.createGroup(groupWithDetails) instead

                if (!isProtectedGroup(groupName, config)) {
                    Long groupId =
                        provider.createGroup(groupName, groupPermissions, strictModeOn);
                    log.debug("[external_auth] Provider returned group: {} with id: {} for user: {}",
                              groupName, groupId, username);

                    result.add(groupId);
                }
            }

        }

        return result;
    }

    private boolean isProtectedGroup(String groupName, ExternalAuthConfig config) {
        Check.notEmpty(groupName, "groupName");
        Check.notNull(config, "authConfig");

        boolean result = false;

        List<String> excludedGroups = config.listExcludedGroups();
        if (null != excludedGroups) {

            result = excludedGroups.contains(groupName);
            log.debug("[external_auth] isProtectedGroup? {} : {}", groupName, result);

        }

        return result;
    }

}
