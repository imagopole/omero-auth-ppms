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

    PpmsUserDetails findUserAndGroupByName(String userName) throws PumapiException;

    List<NamedItem> findProjectsByUserName(String userName) throws PumapiException;

    /**
     * Retrieves a PPMS groups (a.k.a Units) for a PPMS user.
     *
     * @param userName the username / PPMS identifier
     * @return a groups/unit or null if none found.
     * @throws PumapiException in case of an underlying error (API or technical)
     */
    PpmsGroup findGroupByUserName(String userName) throws PumapiException;

    /**
     * Retrieves a list of PPMS instruments (a.k.a Systems) available to a given user.
     *
     * @param userName the username / PPMS identifier
     * @return a list of instrument attributes, or an empty list if none found
     * @throws PumapiException in case of an underlying error (API or technical)
     */
    List<PpmsSystem> findSystemsByUserName(String userName) throws PumapiException;

    /**
     * Retrieves a list of PPMS instruments (a.k.a Systems) available to a given user with an
     * autonomy status on the instrument.
     *
     * @param userName the username / PPMS identifier
     * @return a list of granted instrument attributes, or an empty list if none found
     * @throws PumapiException
     */
    List<PpmsSystem> findSystemsWithAutonomyByUserName(String userName) throws PumapiException;

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
