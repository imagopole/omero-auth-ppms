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
     * Checks the provider for existence of a valid user name.
     *
     * This gives strictly no indication whether this provider "considers itself responsible for
     * the given user name", as this is handled by {@link #hasPassword(String)}.
     * It merely checks for presence of the user account (and possibly its validity - eg.
     * expiration, locking, etc.)
     *
     * Despite some overlap with its password counterpart, this method allows to verify the
     * existence of an account independently of the account/password ownership rules.
     *
     * @param user the experimenter login
     * @return true if a valid user account is known by this provider, false otherwise
     */
    boolean hasUsername(String user);

    /**
     * Replicates additional information for the given user into OMERO.
     *
     * Only accounts which this provider {@link #hasUsername(String)} for should be considered
     * as candidates for synchronization.
     *
     * @param username the experimenter login
     */
    void synchronizeUser(String username);

}
