/**
 *
 */
package org.imagopole.omero.auth.api.group;

import java.util.List;

import ome.security.auth.RoleProvider;

import org.imagopole.omero.auth.api.ExternalAuthConfig;
import org.imagopole.omero.auth.api.ExternalServiceException;

/**
 * Strategy for finding the appropriate groups for a given user in an external roles data source.
 *
 * Modeled after the {@link ome.security.auth.NewUserGroupBean} API in use with an LDAP source, with the only
 * differences being the removal or replacement of LDAP-specific arguments.
 *
 * @author seb
 *
 */
public interface ExternalNewUserGroupBean {

    /**
     * Looks up the group memberships for a given OMERO user from an a external data source,
     * creates them in OMERO if necessary, and returns their identifiers.
     *
     * @param username the OMERO username to lookup in the remote source
     * @param config the external source configuration settings
     * @param provider the OMERO role provider service
     * @return a list of OMERO group identifiers the user is a member of in the external source, or
     * an empty list if no memberships exist.
     * @throws ExternalServiceException in case of an underlying error during the remote service call
     */
    List<Long> groups(String username, ExternalAuthConfig config, RoleProvider provider) throws ExternalServiceException;

}
