/**
 *
 */
package org.imagopole.omero.auth.impl.ppms.group;


import java.util.List;

import ome.security.auth.NewUserGroupBean;

import org.imagopole.omero.auth.api.ExternalAuthConfig;
import org.imagopole.omero.auth.api.dto.NamedItem;
import org.imagopole.omero.auth.api.ppms.PpmsService;
import org.imagopole.omero.auth.impl.DefaultExternalAuthConfig.ConfigValues;
import org.imagopole.omero.auth.impl.group.ConfigurableNameToGroupBean;
import org.imagopole.omero.auth.impl.ppms.PpmsUtil;
import org.imagopole.ppms.api.dto.PpmsSystem;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * A {@link NewUserGroupBean} implementation which allows mapping of a PPMS system (a.k.a instrument)
 * regardless of any granted user privilege to an OMERO group.
 *
 * Additional filters may apply to restrict the available instruments by core facility or type.
 *
 * @author seb
 *
 */
public class PpmsSystemToGroupBean extends ConfigurableNameToGroupBean {

    /** Application logs. */
    private final Logger log = LoggerFactory.getLogger(PpmsSystemToGroupBean.class);

    /** Service layer for PPMS/PUMAPI. */
    private PpmsService ppmsService;

    /** Configurable permission level enumeration for use at group creation time.
     *  @see ConfigValues */
    private String permissionLevel;

    /**
     * Vanilla constructor.
     */
    public PpmsSystemToGroupBean() {
        super();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    protected List<NamedItem> listItemsByUserName(String username, ExternalAuthConfig config) {
        log.debug("[external_auth][ppms] looking up PPMS systems available for username: {}", username);

        List<PpmsSystem> grantedSystems = getPpmsService().findActiveSystemsByUserName(username);

        // only retain systems which belong to whitelists of enabled facilities and system types
        List<PpmsSystem> filteredSystems = PpmsUtil.filterSystemsByFacilityAndType(grantedSystems, config);

        return PpmsUtil.toNamedItems(filteredSystems);
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
