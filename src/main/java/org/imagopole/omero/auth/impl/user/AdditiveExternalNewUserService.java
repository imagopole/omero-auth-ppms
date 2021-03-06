/**
 *
 */
package org.imagopole.omero.auth.impl.user;

import java.util.List;
import java.util.Set;

import ome.model.meta.Experimenter;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.transaction.annotation.Transactional;

/**
 * {@link org.imagopole.omero.auth.api.user.ExternalNewUserService} implementation whereby
 * the external source is "conservative"/append only:
 * - group memberships already present in OMERO but missing from the external data source are preserved
 * rather than being unlinked.
 * - group memberships missing in OMERO but present in the external source are added.
 *
 * This differs from the {@link ome.security.auth.LdapPasswordProvider} behaviour in that it allows
 *  for local OMERO data to be preserved upon synchronization.
 *
 * @author seb
 *
 */
@Transactional
public abstract class AdditiveExternalNewUserService extends BaseExternalNewUserService {

    /** Application logs. */
    private final Logger log = LoggerFactory.getLogger(AdditiveExternalNewUserService.class);

    /**
     * {@inheritDoc}
     */
    @Override
    public void synchronizeGroupsMemberships(
                    final Experimenter omeroExperimenter,
                    final Set<Long> omeroGroups,
                    final List<Long> externalGroups) {

        log.debug("[external_auth] Additively synchronizing groups for experimenter: {}-{}",
                   omeroExperimenter.getId(), omeroExperimenter.getOmeName());

        log.debug("[external_auth] omeroGroups: {}", omeroGroups);
        log.debug("[external_auth] externalGroups: {}", externalGroups);

        // All the omeroGroups not in externalGroups should be removed.
        //modifyGroups(omeExp, omeGroupIds, ldapGroups, false);

        // All the externalGroups not in omeroGroups should be added.
        modifyGroups(omeroExperimenter, externalGroups, omeroGroups, true);
    }

}
