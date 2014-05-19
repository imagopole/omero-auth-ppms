/**
 *
 */
package org.imagopole.omero.auth.impl.ppms.user;

import ome.annotations.RolesAllowed;
import ome.conditions.SecurityViolation;
import ome.model.meta.Experimenter;

import org.imagopole.omero.auth.api.ExternalServiceException;
import org.imagopole.omero.auth.api.ppms.PpmsService;
import org.imagopole.omero.auth.impl.ppms.PpmsUtil;
import org.imagopole.omero.auth.impl.user.AdditiveExternalNewUserService;
import org.imagopole.omero.auth.util.Check;
import org.imagopole.ppms.api.dto.PpmsUser;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * {@link org.imagopole.omero.auth.api.user.ExternalNewUserService} implementation whereby
 * the external source is a PPMS instance.
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
     * {@inheritDoc}
     */
    @Override
    public boolean validatePassword(String username, String password) throws ExternalServiceException {
        if (Check.empty(username) || Check.empty(password)) {
            throw new SecurityViolation("Refused to authenticate without username and password!");
        }

        // note: PPMS authentication will fail if the user has been marked as inactive
        boolean success = getPpmsService().checkAuthentication(username, password);
        log.debug("[external_auth][ppms] external user authentication result for username {} : {}",
                  username, success);

        return success;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    @RolesAllowed("system")
    public Experimenter findExperimenterFromExternalSource(String username) throws ExternalServiceException {
        Check.notEmpty(username, "username");

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
