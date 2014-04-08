/**
 *
 */
package org.imagopole.omero.auth.impl.ppms.group;


import java.util.ArrayList;
import java.util.List;

import ome.security.auth.NewUserGroupBean;

import org.imagopole.omero.auth.api.ExternalAuthConfig;
import org.imagopole.omero.auth.api.dto.NamedItem;
import org.imagopole.omero.auth.api.ppms.PpmsService;
import org.imagopole.omero.auth.impl.group.ConfigurableNameToGroupBean;
import org.imagopole.ppms.api.dto.PpmsGroup;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * A {@link NewUserGroupBean} implementation which allows mapping of a PPMS unit (a.k.a group) to an OMERO group.
 *
 * @author seb
 *
 */
public class PpmsUnitToGroupBean extends ConfigurableNameToGroupBean {

    /** Application logs. */
    private final Logger log = LoggerFactory.getLogger(PpmsUnitToGroupBean.class);

    /** Service layer for PPMS/PUMAPI. */
    private PpmsService ppmsService;

    /** Configurable permission level enumeration for use at group creation time.
     *  @see ConfigValues */
    private String permissionLevel;

    /**
     * Vanilla constructor.
     */
    public PpmsUnitToGroupBean() {
        super();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    protected List<NamedItem> listItemsByUserName(String username, ExternalAuthConfig config) {
        log.debug("[external_auth][ppms] looking up PPMS groups/units for username: {}", username);

        List<NamedItem> result = new ArrayList<NamedItem>();

        PpmsGroup unit = getPpmsService().findGroupByUserName(username);
        if (null != unit) {

            String groupId = unit.getUnitlogin();
            String groupName = unit.getUnitname();
            result.add(NamedItem.newItem(groupId, groupName, "[ppms]"));

        }

        return result;
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
     * Returns ppmsService.
     * @return the ppmsService
     */
    public PpmsService getPpmsService() {
        return ppmsService;
    }

    /**
     * Sets ppmsService.
     * @param ppmsService the ppmsService to set
     */
    public void setPpmsService(PpmsService ppmsService) {
        this.ppmsService = ppmsService;
    }

}
