/**
 *
 */
package org.imagopole.omero.auth.impl.ppms.group;


import java.util.List;

import org.imagopole.omero.auth.api.ExternalAuthConfig;
import org.imagopole.omero.auth.api.dto.NamedItem;
import org.imagopole.omero.auth.api.ppms.PpmsService;
import org.imagopole.omero.auth.impl.group.ConfigurableNameToGroupBean;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * A {@link ome.security.auth.NewUserGroupBean} implementation which allows mapping of
 * a PPMS Project to an OMERO group.
 *
 * @author seb
 *
 */
public class PpmsProjectToGroupBean extends ConfigurableNameToGroupBean {

    /** Application logs. */
    private final Logger log = LoggerFactory.getLogger(PpmsProjectToGroupBean.class);

    /** Service layer for PPMS/PUMAPI. */
    private PpmsService ppmsService;

    /** Configurable permission level enumeration for use at group creation time.
     *
     *  @see org.imagopole.omero.auth.impl.DefaultExternalAuthConfig.ConfigValues */
    private String permissionLevel;

    /**
     * Vanilla constructor.
     */
    public PpmsProjectToGroupBean() {
        super();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    protected List<NamedItem> listItemsByUserName(String username, ExternalAuthConfig config) {
        log.debug("[external_auth][ppms] looking up PPMS projects for username: {}", username);

        return getPpmsService().findProjectsByUserName(username);
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
