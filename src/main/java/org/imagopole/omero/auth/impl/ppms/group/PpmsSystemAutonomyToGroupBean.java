/**
 *
 */
package org.imagopole.omero.auth.impl.ppms.group;


import static org.imagopole.omero.auth.impl.ppms.PpmsUtil.filterSystemsByFacilityAndType;
import static org.imagopole.omero.auth.impl.ppms.PpmsUtil.toNamedItems;

import java.util.List;

import org.imagopole.omero.auth.api.ExternalAuthConfig;
import org.imagopole.omero.auth.api.dto.NamedItem;
import org.imagopole.omero.auth.api.ppms.PpmsService;
import org.imagopole.omero.auth.impl.group.ConfigurableNameToGroupBean;
import org.imagopole.ppms.api.dto.PpmsSystem;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A {@link ome.security.auth.NewUserGroupBean} implementation which allows mapping
 * of a PPMS system (a.k.a instrument) for which the user has been granted an
 * "autonomous" privilege to an OMERO group.
 *
 * Additional filters may apply to restrict the available instruments by core facility or type.
 *
 * @author seb
 *
 */
public class PpmsSystemAutonomyToGroupBean extends ConfigurableNameToGroupBean {

    /** Application logs. */
    private final Logger log = LoggerFactory.getLogger(PpmsSystemAutonomyToGroupBean.class);

    /** Service layer for PPMS/PUMAPI. */
    private PpmsService ppmsService;

    /** Configurable permission level enumeration for use at group creation time.
     *  @see org.imagopole.omero.auth.impl.DefaultExternalAuthConfig.ConfigValues */
    private String permissionLevel;

    /**
     * Vanilla constructor.
     */
    public PpmsSystemAutonomyToGroupBean() {
        super();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    protected List<NamedItem> listItemsByUserName(String username, ExternalAuthConfig config) {
        log.debug("[external_auth][ppms] looking up active PPMS systems with autonomy for username: {}",
                  username);

        List<PpmsSystem> grantedSystems =
            getPpmsService().findActiveSystemsWithAutonomyByUserName(username);

        // only retain systems which belong to whitelists of enabled facilities and system types
        List<PpmsSystem> filteredSystems = filterSystemsByFacilityAndType(grantedSystems, config);

        return toNamedItems(filteredSystems);
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
