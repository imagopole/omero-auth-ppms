/**
 *
 */
package org.imagopole.omero.auth.impl.ppms.user;

import java.text.MessageFormat;

import ome.annotations.RolesAllowed;
import ome.conditions.SecurityViolation;
import ome.model.meta.Experimenter;
import ome.security.auth.RoleProvider;
import ome.system.Roles;
import ome.util.SqlAction;

import org.imagopole.omero.auth.api.ExternalAuthConfig;
import org.imagopole.omero.auth.api.ppms.PpmsService;
import org.imagopole.omero.auth.api.ppms.PpmsUserDetails;
import org.imagopole.omero.auth.api.user.ExternalNewUserService;
import org.imagopole.omero.auth.impl.ppms.PpmsUtil;
import org.imagopole.omero.auth.impl.user.AdditiveExternalNewUserService;
import org.imagopole.omero.auth.util.ConvertUtil;
import org.imagopole.ppms.api.dto.PpmsGroup;
import org.imagopole.ppms.api.dto.PpmsUser;
import org.imagopole.ppms.util.Check;
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
     * @param sqlAction OMERO SQL service
     */
    public PpmsExternalNewUserService(
        Roles roles, ExternalAuthConfig config, RoleProvider roleProvider, SqlAction sqlAction) {
        super(roles, config, roleProvider, sqlAction);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public boolean validatePassword(String username, String password) {
        // See discussion on anonymous bind in LdapPasswordProvider
        if (username == null || username.trim().isEmpty() ||
            password == null || password.trim().isEmpty()) {
            throw new SecurityViolation(
                  "Refused to authenticate without username and password!");
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
    public Experimenter findExperimenterFromExternalSource(String username) {
        Experimenter person = null;

        PpmsUser ppmsUser = getPpmsService().findUserByName(username);
        log.debug("[external_auth][ppms] external user lookup result for username {} : {}",
                  username, ppmsUser);

        if (null != ppmsUser) {

            person = PpmsUtil.toExperimenter(ppmsUser);

        }

        return person;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    @RolesAllowed("system")
    public Experimenter findExperimenterDetailsFromExternalSource(String username) {
        Experimenter person = null;

        PpmsUserDetails details = getPpmsService().findUserAndGroupByName(username);
        log.debug("[external_auth][ppms] external user details result for username {} : {}",
                  username, details);

        if (null != details) {

            PpmsUser ppmsUser = details.getUser();
            PpmsGroup ppmsGroup = details.getGroup();

            log.debug("[external_auth][ppms] preparing to add details for user: {} of group: {}",
                      ppmsUser, ppmsGroup);

            if (null != ppmsUser) {

                person = PpmsUtil.toExperimenter(ppmsUser);

                if (null != ppmsGroup) {

                    boolean isExternalUser = details.isExternalAffiliation();
                    addExperimenterDetails(person, ppmsGroup, isExternalUser);

                }
            }

        }

        return person;
    }

    private void addExperimenterDetails(
        Experimenter person, PpmsGroup ppmsGroup, boolean isExternalUser) {

        Check.notNull(person, "person");
        Check.notNull(ppmsGroup, "ppmsGroup");

        String username = person.getOmeName();
        boolean isLdapDnSeedEnabled = config.seedLdapDn();

        // only pre-seed the DN for users which are supposed to have a LDAP account
        // (ie. filter out users with an external affiliation)
        boolean shouldSeedDn = isLdapDnSeedEnabled && !isExternalUser;

        if (shouldSeedDn) {

            String experimenterDn = findExperimenterLdapDnOrFail(username);
            log.debug("[external_auth][ppms] retrieved LDAP DN: {} for user+group {}@{}",
                       experimenterDn, username, ppmsGroup.getUnitlogin());

            person.putAt(ConvertUtil.DN_FIELD, experimenterDn);

        } else {
            log.debug("[external_auth][ppms] skipping LDAP DN details for x-user+group {}@{} [seedDn:{}]",
                      username, ppmsGroup.getUnitlogin(), isLdapDnSeedEnabled);
        }

        person.setInstitution(String.format("ppms:%s", ppmsGroup.getUnitlogin()));
    }


    private String findExperimenterLdapDnOrFail(String username) {
       Check.notEmpty(username, "username");

       String dnFormat = PpmsUtil.getLdapDnFormat(config);
       log.debug("[external_auth][ppms] retrieved ldap_dn_format: {}", dnFormat);

       Check.notEmpty(dnFormat, "dnFormat");
       String result = MessageFormat.format(dnFormat, username);

       return result;
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
