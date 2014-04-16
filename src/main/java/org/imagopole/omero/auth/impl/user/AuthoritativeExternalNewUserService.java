/**
 *
 */
package org.imagopole.omero.auth.impl.user;

import java.util.List;
import java.util.Set;

import ome.logic.LdapImpl;
import ome.model.meta.Experimenter;
import ome.security.auth.LdapPasswordProvider;
import ome.security.auth.RoleProvider;
import ome.system.Roles;

import org.imagopole.omero.auth.api.ExternalAuthConfig;
import org.imagopole.omero.auth.api.user.ExternalNewUserService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * {@link ExternalNewUserService} implementation whereby the external source is "authoritative"/override always:
 * - group memberships already present in OMERO but missing from the external data source are unlinked.
 * - group memberships missing in OMERO but present in the external source are added.
 *
 * This emulates the {@link LdapImpl} behaviour when used with {@link LdapPasswordProvider} and
 * <code>omero.ldap.sync_on_login=true</code>.
 *
 * @author seb
 *
 */
public abstract class AuthoritativeExternalNewUserService extends BaseExternalNewUserService {

    /** Application logs. */
    private final Logger log = LoggerFactory.getLogger(AuthoritativeExternalNewUserService.class);

    /**
     * Full constructor.
     *
     * @param roles OMERO roles for superclass
     * @param config external extension configuration settings
     * @param roleProvider OMERO roles service
     */
    public AuthoritativeExternalNewUserService(
        Roles roles, ExternalAuthConfig config, RoleProvider roleProvider) {
        super(roles, config, roleProvider);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void synchronizeGroupsMemberships(
                    Experimenter omeroExperimenter,
                    Set<Long> omeroGroups,
                    List<Long> externalGroups) {

        log.debug("[external_auth] Authoritatively synchronizing groups for experimenter: {}-{}",
                  omeroExperimenter.getId(), omeroExperimenter.getOmeName());

        // All the omeroGroups not in externalGroups should be removed.
        modifyGroups(omeroExperimenter, omeroGroups, externalGroups, false);

        // All the externalGroups not in omeroGroups should be added.
        modifyGroups(omeroExperimenter, externalGroups, omeroGroups, true);

    }

}
