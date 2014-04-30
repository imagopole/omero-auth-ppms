/**
 *
 */
package org.imagopole.omero.auth.impl.ppms;

import static org.imagopole.ppms.util.Check.empty;

import java.util.ArrayList;
import java.util.List;

import org.imagopole.omero.auth.api.dto.NamedItem;
import org.imagopole.omero.auth.api.ppms.PpmsService;
import org.imagopole.omero.auth.api.ppms.PpmsUserDetails;
import org.imagopole.ppms.api.PumapiClient;
import org.imagopole.ppms.api.PumapiException;
import org.imagopole.ppms.api.dto.PpmsGroup;
import org.imagopole.ppms.api.dto.PpmsPrivilege;
import org.imagopole.ppms.api.dto.PpmsSystem;
import org.imagopole.ppms.api.dto.PpmsUser;
import org.imagopole.ppms.api.dto.PpmsUserPrivilege;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Provides a facade to the underlying services published by the PPMS/PUMAPI HTTP client.
 *
 * Methods may aggregate more than one remote API calls.
 *
 * @author seb
 *
 */
public class DefaultPpmsService implements PpmsService {

    /** Application logs */
    private final Logger log = LoggerFactory.getLogger(DefaultPpmsService.class);

    /** PPMS web client */
    private PumapiClient ppmsClient;

    /**
     * Default constructor.
     */
    public DefaultPpmsService() {
        super();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public PpmsUser findUserByName(String userName) throws PumapiException {
        // lookup the user basic info
        PpmsUser ppmsUser = getPpmsClient().getUser(userName);

        return ppmsUser;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public boolean checkAuthentication(String userName, String password) throws PumapiException {
        Boolean success = getPpmsClient().authenticate(userName, password);

        return success;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public List<NamedItem> findProjectsByUserName(String userName) throws PumapiException {
        throw new UnsupportedOperationException("Projects lookup by login not implemented");
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public PpmsGroup findGroupByUserName(String userName) throws PumapiException {
        PpmsGroup result = null;

        // finding the group always requires looking up the user first to get hold of the "unitlogin"
        PpmsUserDetails details = findUserAndGroupByName(userName);

        if (null != details) {

            result = details.getGroup();

        }

        return result;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public PpmsUserDetails findUserAndGroupByName(String userName) throws PumapiException {
        PpmsUserDetails result = null;

        // lookup the user basic info
        PpmsUser ppmsUser = getPpmsClient().getUser(userName);

        // extract the PPMS group ID the user belongs to
        if (null != ppmsUser) {

            String ppmsGroupKey = ppmsUser.getUnitlogin();
            if (!empty(ppmsGroupKey)) {

                // lookup the PPMS group ("unit") details
                PpmsGroup ppmsGroup = getPpmsClient().getGroup(ppmsGroupKey);
                if (null != ppmsGroup) {

                    result = new PpmsUserDetails(ppmsUser, ppmsGroup);

                } else {

                    result = new PpmsUserDetails(ppmsUser);
                    log.warn("[external_auth][ppms] Null PPMS group details for username: {}", userName);

                }

            } else {
                log.warn("[external_auth][ppms] Empty PPMS group key (unitlogin) for username: {}", userName);
            }

        } else {
            log.warn("[external_auth][ppms] Null PPMS user details for username: {}", userName);
        }

       return result;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public List<PpmsSystem> findActiveSystemsByUserName(String userName) throws PumapiException {
        List<PpmsSystem> result = new ArrayList<PpmsSystem>();

        // get the list of PPMS "systems" IDs available to the user
        List<PpmsUserPrivilege> grantedIntruments = getPpmsClient().getUserRights(userName);

        // include them regardless of his/her autonomy status (may be autonomous,
        // superuser, novice or deactivated)
        if (null != grantedIntruments && !grantedIntruments.isEmpty()) {

            for (PpmsUserPrivilege grantedSystem : grantedIntruments) {
                Long systemId = grantedSystem.getSystemId();

                // lookup the systems' details (name, description...)
                PpmsSystem system = getPpmsClient().getSystem(systemId);

                if (null != system) {
                    boolean isSystemActive = (null != system.getActive() && system.getActive());

                    if (isSystemActive) {
                        result.add(system);
                    } else {
                        log.warn("[external_auth][ppms] Inactive system: {}-{} granted to username: {}",
                                 system.getSystemId(), system.getName(), userName);
                    }
                }
            }

        } else {
            log.warn("[external_auth][ppms] No granted rights for username: {}", userName);
        }

        return result;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public List<PpmsSystem> findActiveSystemsWithAutonomyByUserName(String userName) throws PumapiException {
        List<PpmsSystem> result = new ArrayList<PpmsSystem>();

        // get the list of PPMS "systems" IDs available to the user
        List<PpmsUserPrivilege> grantedIntruments = getPpmsClient().getUserRights(userName);

        // include them taking into account both his/her autonomy status and the autonomy requirements
        // defined on the instrument itself
        if (null != grantedIntruments && !grantedIntruments.isEmpty()) {

            for (PpmsUserPrivilege grantedSystem : grantedIntruments) {
                Long systemId = grantedSystem.getSystemId();
                PpmsPrivilege systemPrivilege = grantedSystem.getPrivilege();

                // lookup the systems' details (name, description...)
                PpmsSystem system = getPpmsClient().getSystem(systemId);

                if (null != system) {

                    boolean isSystemActive =
                        (null != system.getActive() && system.getActive());
                    boolean isAutonomyRequired =
                        (null != system.getAutonomyRequired() && system.getAutonomyRequired());

                    boolean isAutonomyGranted =
                        PpmsPrivilege.Autonomous.equals(systemPrivilege)
                        || PpmsPrivilege.SuperUser.equals(systemPrivilege);
                    boolean isUserActivated = !PpmsPrivilege.Deactivated.equals(systemPrivilege);

                    log.debug(
                        "[external_auth][ppms] Autonomy filters for: {} on system: {}-{} [required:{} - granted:{} - activated:{} - active:{}]",
                        userName, systemId, system.getName(), isAutonomyRequired, isAutonomyGranted, isUserActivated, isSystemActive);

                    if (isSystemActive) {

                        // the instrument on this facility requires autonomy before user access
                        if (isAutonomyRequired) {
                            if (isAutonomyGranted) {
                                result.add(system);
                            }
                        } else {
                            // any user may access this instrument, regardless of whether they are autonomous
                            // we only exclude deactivated users here
                            if (isUserActivated) {
                                result.add(system);
                            }
                        }

                    } else {
                        log.warn("[external_auth][ppms] Inactive system: {}-{} granted to username: {}",
                                 system.getSystemId(), system.getName(), userName);
                    }

                }

            }

        } else {
            log.warn("[external_auth][ppms] No granted rights for username: {}", userName);
        }

        return result;
    }

    /**
     * Returns ppmsClient.
     * @return the ppmsClient
     */
    public PumapiClient getPpmsClient() {
        return ppmsClient;
    }

    /**
     * Sets ppmsClient.
     * @param ppmsClient the ppmsClient to set
     */
    public void setPpmsClient(PumapiClient ppmsClient) {
        this.ppmsClient = ppmsClient;
    }

}
