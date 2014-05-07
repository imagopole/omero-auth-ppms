/**
 *
 */
package org.imagopole.omero.auth.impl.ppms.user;

import ome.annotations.RolesAllowed;
import ome.conditions.SecurityViolation;
import ome.model.meta.Experimenter;
import ome.security.auth.RoleProvider;
import ome.system.Roles;

import org.imagopole.omero.auth.api.ExternalAuthConfig;
import org.imagopole.omero.auth.api.ExternalServiceException;
import org.imagopole.omero.auth.api.ppms.PpmsService;
import org.imagopole.omero.auth.api.user.ExternalNewUserService;
import org.imagopole.omero.auth.impl.ppms.PpmsUtil;
import org.imagopole.omero.auth.impl.user.AdditiveExternalNewUserService;
import org.imagopole.ppms.api.dto.PpmsUser;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * {@link ExternalNewUserService} implementation whereby the external source is a PPMS instance.
 *
 * @author seb
 *
 */
public class PpmsExternalNewUserService extends AdditiveExternalNewUserService {

    /** Application logs. */
    private final Logger log = LoggerFactory.getLogger(PpmsExternalNewUserService.class);

    /** Service layer for PPMS/PUMAPI. */
    private PpmsService ppmsService;

    /**
     * Full constructor.
     *
     * @param roles OMERO roles for superclass
     * @param config external extension configuration settings
     * @param roleProvider OMERO roles service
     */
    public PpmsExternalNewUserService(
        Roles roles, ExternalAuthConfig config, RoleProvider roleProvider) {
        super(roles, config, roleProvider);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public boolean validatePassword(String username, String password) throws ExternalServiceException {
        // See discussion on anonymous bind in LdapPasswordProvider
        if (username == null || username.trim().isEmpty() ||
            password == null || password.trim().isEmpty()) {
            throw new SecurityViolation("Refused to authenticate without username and password!");
        }

        // note: PPMS authentication will fail if the user has been marked as inactive
        boolean success = getPpmsService().checkAuthentication(username, password);
        log.debug("[external_auth ][ppms] external user authentication result for username {} : {}",
                  username, success);

        return success;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    @RolesAllowed("system")
    public Experimenter findExperimenterFromExternalSource(String username) throws ExternalServiceException {
        Experimenter person = null;

        PpmsUser ppmsUser = getPpmsService().findUserByName(username);
        log.debug("[external_auth][ppms] external user lookup result for username {} : {}",
                  username, ppmsUser);

        if (null != ppmsUser) {

            boolean isActiveUser = (null != ppmsUser.getActive() && ppmsUser.getActive());

            if (isActiveUser) {

                person = PpmsUtil.toExperimenter(ppmsUser);

            } else {
                log.info("[external_auth][ppms] Ignoring inactive external username: {}", username);
            }

        }

        return person;
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
