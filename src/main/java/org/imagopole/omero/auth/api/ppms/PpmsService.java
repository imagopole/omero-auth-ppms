/**
 *
 */
package org.imagopole.omero.auth.api.ppms;

import java.util.List;

import org.imagopole.omero.auth.api.dto.NamedItem;
import org.imagopole.ppms.api.PumapiException;
import org.imagopole.ppms.api.dto.PpmsGroup;
import org.imagopole.ppms.api.dto.PpmsSystem;
import org.imagopole.ppms.api.dto.PpmsUser;

/**
 * Provides a facade to the underlying services published by the PPMS/PUMAPI client.
 *
 * Methods may aggregate more than one remote API calls.
 *
 * @author seb
 *
 */
public interface PpmsService {

    /**
     * Retrieves a PPMS user by login.
     *
     * @param userName the username / PPMS identifier
     * @return the user attributes or null if not found.
     * @throws PumapiException in case of an underlying error (API or technical)
     */
    PpmsUser findUserByName(String userName) throws PumapiException;

    /**
     * Retrieves a PPMS user by login, with affiliation details, regardless of the group's or
     * the user's statuses (active or inactive).
     *
     * @param userName the username / PPMS identifier
     * @return the user attributes or null if not found.
     * @throws PumapiException in case of an underlying error (API or technical)
     */
    PpmsUserDetails findUserAndGroupByName(String userName) throws PumapiException;

    // not implemented yet - will likely return a PpmsProject entity later
    List<NamedItem> findProjectsByUserName(String userName) throws PumapiException;

    /**
     * Retrieves the PPMS group (a.k.a Unit) for a PPMS user, regardless of the group's or
     * the user's statuses (active or inactive).
     *
     * @param userName the username / PPMS identifier
     * @return a groups/unit or null if none found.
     * @throws PumapiException in case of an underlying error (API or technical)
     */
    PpmsGroup findGroupByUserName(String userName) throws PumapiException;

    /**
     * Retrieves a list of active PPMS instruments (a.k.a Systems) available to a given user with
     * a status other than deactivated on the instrument.
     *
     * The instrument's autonomy requirements are not taken into account.
     *
     * @param userName the username / PPMS identifier
     * @return a list of instrument attributes, or an empty list if none found
     * @throws PumapiException in case of an underlying error (API or technical)
     */
    List<PpmsSystem> findActiveSystemsByUserName(String userName) throws PumapiException;

    /**
     * Retrieves a list of active PPMS instruments (a.k.a Systems) available to a given user with an
     * autonomy status (or super user status) on the instrument.
     *
     * The instrument's autonomy requirements are taken into account.
     *
     * @param userName the username / PPMS identifier
     * @return a list of granted instrument attributes, or an empty list if none found
     * @throws PumapiException
     */
    List<PpmsSystem> findActiveSystemsWithAutonomyByUserName(String userName) throws PumapiException;

    /**
     * Validates password for a PPMS user.
     *
     * @param userName the username / PPMS identifier
     * @param password the plain-text password
     * @return true if the password check succeeded, false otherwise
     * @throws PumapiException in case of an underlying error (API or technical)
     */
    boolean checkAuthentication(String userName, String password) throws PumapiException;

}
