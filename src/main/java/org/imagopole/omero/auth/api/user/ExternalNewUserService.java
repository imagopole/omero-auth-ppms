/**
 *
 */
package org.imagopole.omero.auth.api.user;

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
     *
     * @param username
     * @return
     *
     * @see ome.logic.LdapImpl#findExperimenter(String)
     */
    Experimenter findExperimenterFromExternalSource(String username);

    /**
     * Identical to {@link #findExperimenterFromExternalSource(String)}, with additional information
     * related to:
     * - internal/external status. Implementation-dependent - eg. materialized as an extra <code>dn</code> field.
     * - affiliation/institution
     *
     * @param username
     * @return
     */
    Experimenter findExperimenterDetailsFromExternalSource(String username);

    /**
     *
     * @param username
     * @param password
     * @return
     *
     * @see ome.logic.LdapImpl#createUserFromLdap(String, String)
     */
    boolean createUserFromExternalSource(String username, String password);

    /**
     *
     * @param username
     *
     * @see ome.logic.LdapImpl#synchronizeLdapUser(String)
     */
    void synchronizeUserFromExternalSource(String username);

    /**
     *
     * @param username
     * @param password
     * @return
     *
     * @see ome.logic.LdapImpl#validatePassword(String, String)
     */
    boolean validatePassword(String username, String password);

}
