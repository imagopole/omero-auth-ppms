/**
 *
 */
package org.imagopole.omero.auth.impl;

import ome.model.internal.Permissions;
import ome.model.meta.Experimenter;
import ome.model.meta.ExperimenterGroup;
import ome.model.meta.ExternalInfo;
import ome.security.SecuritySystem;
import ome.security.auth.SimpleRoleProvider;
import ome.tools.hibernate.SessionFactory;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * An extension to {@link SimpleRoleProvider} which allows "deeper" object copies for
 * {@link Experimenter} and {@link ExperimenterGroup}.
 *
 * This implementation overrides the <code>copyUser</code> and <code>copyGroup</code> methods
 * to include cloning of the user or group's {@link ExternalInfo} data (if it is present).
 *
 * @author seb
 *
 */
public class ExternalInfoRoleProvider extends SimpleRoleProvider {

    /** Application logs. */
    private final Logger log = LoggerFactory.getLogger(ExternalInfoRoleProvider.class);

    /**
     * Paremeterized constructor.
     *
     * @param sec OMERO security system
     * @param sf Hibernate session factory
     */
    public ExternalInfoRoleProvider(SecuritySystem sec, SessionFactory sf) {
        super(sec, sf);
    }

    /**
     * Identical to {@link SimpleRoleProvider}, with additional fields being copied
     * to include {@link ExternalInfo} details.
     *
     * @see ome.security.auth.SimpleRoleProvider#copyGroup(ome.model.meta.ExperimenterGroup)
     */
    @Override
    protected ExperimenterGroup copyGroup(ExperimenterGroup g) {
        ExperimenterGroup copy = super.copyGroup(g);

        // TODO: CHECKME should the external info be deep cloned too?
        ExternalInfo externalInfo = g.getDetails().getExternalInfo();
        if (null != externalInfo) {

            log.debug("[external_auth] Deep-copying external info: {} for group: {}", externalInfo, g);
            copy.getDetails().setExternalInfo(externalInfo);

            Permissions groupPermissions = g.getDetails().getPermissions();
            copyPermissionsIfMissing(externalInfo, groupPermissions);

        }

        return copy;
    }

    /**
     * Identical to {@link SimpleRoleProvider}, with additional fields being copied
     * to include {@link ExternalInfo} details.
     *
     * @see ome.security.auth.SimpleRoleProvider#copyUser(ome.model.meta.Experimenter)
     */
    @Override
    protected Experimenter copyUser(Experimenter e) {
        Experimenter copy = super.copyUser(e);

        // TODO: CHECKME should the external info be deep cloned too?
        ExternalInfo externalInfo = e.getDetails().getExternalInfo();
        if (null != externalInfo) {

            log.debug("[external_auth] Deep-copying external info: {} for user: {}", externalInfo, e);
            copy.getDetails().setExternalInfo(externalInfo);

            Permissions groupPermissions = e.getDetails().getPermissions();
            copyPermissionsIfMissing(externalInfo, groupPermissions);

        }

        return copy;
    }

    /**
     * @param externalInfo
     * @param currentPermissions
     */
    private void copyPermissionsIfMissing(ExternalInfo externalInfo, Permissions currentPermissions) {
        Permissions externalPermissions = externalInfo.getDetails().getPermissions();

        if (null == externalPermissions && null != currentPermissions) {

            log.debug("[external_auth] Carrying over permissions: {} to external info: {}",
                      currentPermissions, externalInfo);
            externalInfo.getDetails().setPermissions(currentPermissions);

        }
    }

}
