/**
 *
 */
package org.imagopole.omero.auth.api.user;

import org.imagopole.omero.auth.api.ExternalAuthConfig;

import ome.api.ServiceInterface;
import ome.model.meta.Experimenter;
import ome.security.auth.LdapPasswordProvider;
import ome.security.auth.PasswordProvider;


/**
 * OMERO service for user accounts synchronization from an external authentication/authorisation source.
 *
 * Intended for use in combination with a {@link PasswordProvider} implementation.
 * Also marked as a {@link ServiceInterface} to enable deployment as an
 * OMERO {@link ome.system.SelfConfigurableService}, as is the case for {@link ome.logic.LdapImpl}.
 *
 * The public API has been modeled after and extracted from the account creation/replication
 * lifecycle currently in use with the combination of {@link LdapPasswordProvider} and
 * {@link ome.logic.LdapImpl}, so all "external" methods reflect an "ldap impl" equivalent.
 *
 * @author seb
 *
 */
public interface ExternalNewUserService extends ServiceInterface {

    /**
     * Is the external authentication module active?
     *
     * @see ome.logic.LdapImpl#getSetting()
     **/
    boolean isEnabled();

    /**
     * Looks up an experimenter by login.
     *
     * @param username the username / external identifier
     * @return the experimenter, or null if none found
     *
     * @see ome.logic.LdapImpl#findExperimenter(String)
     */
    Experimenter findExperimenterFromExternalSource(String username);

    /**
     * Initializes a new user account in OMERO from the external source.
     *
     * Note that the initialization is performed only if the user's credentials are verified
     * by {@link #validatePassword(String, String)}.
     *
     * This initialization will subsequently trigger groups initialization, and memberships assignment.
     *
     * @param username the username / external identifier
     * @param password the password
     * @return true if the password check succeeded, false otherwise
     *
     * @see ome.logic.LdapImpl#createUserFromLdap(String, String)
     * @see ome.logic.LdapImpl#loadLdapGroups(String, org.springframework.ldap.core.DistinguishedName)
     */
    boolean createUserFromExternalSource(String username, String password);

    /**
     * Updates an existing OMERO user account from the external source.
     *
     * Note that the synchronization is performed only if the service is configured accordingly
     * via {@link ExternalAuthConfig#isSyncOnLogin()}, and if a user is present in the remote source.
     *
     * This synchronization will subsequently trigger groups and memberships creation and assignment
     * as done upon {@link #createUserFromExternalSource(String, String)}. Besides, the experimenter's
     * metadata synchronization will be triggered for the relevant attributes (name, email, institution).
     *
     * @param username the username / external identifier
     *
     * @see ome.logic.LdapImpl#synchronizeLdapUser(String)
     */
    void synchronizeUserFromExternalSource(String username);

    /**
     * Checks the experimenter credentials.
     *
     * @param username the username / external identifier
     * @param password the password
     * @return true if the password check succeeded, false otherwise
     *
     * @see ome.logic.LdapImpl#validatePassword(String, String)
     */
    boolean validatePassword(String username, String password);

}
