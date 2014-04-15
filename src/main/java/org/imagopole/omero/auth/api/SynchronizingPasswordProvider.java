/**
 *
 */
package org.imagopole.omero.auth.api;

import ome.security.auth.PasswordProvider;

/**
 * A {@link PasswordProvider} specialization which exposes an additional synchronization operation
 * as part of the account management lifecycle.
 *
 * This allows implementors to decouple authentication checking from account metadata replication
 * (eg. user details and granted roles).
 *
 * @author seb
 *
 */
public interface SynchronizingPasswordProvider extends PasswordProvider {

    /**
     * Replicates additional information for the given user into OMERO.
     *
     * @param username the experimenter login
     */
    void synchronizeUser(String username);

}
