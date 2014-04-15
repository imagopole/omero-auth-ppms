/**
 *
 */
package org.imagopole.omero.auth.impl;

import ome.security.auth.LdapPasswordProvider;
import ome.security.auth.PasswordChangeException;
import ome.security.auth.PasswordProvider;
import ome.security.auth.PasswordProviders;

import org.imagopole.omero.auth.api.SynchronizingPasswordProvider;
import org.imagopole.omero.auth.util.Check;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A chaining {@link PasswordProvider} implementation with a two-provider chain and support for
 * account synchronization.
 *
 * Chain invocation logic:
 * 1 - The first provider is used for authentication only (typically intended to be a LDAP provider,
 * which may perform the user account initialization).
 * 2 - If the first provider is not responsible for the account, then check the second provider
 * for authentication.
 * 3 - If authentication was successful with either provider, then also synchronize the account via
 * the second provider.
 *
 * This chaining logic differs from the default {@link PasswordProviders} mostly through the
 * separation of authentication and synchronization - which are typically performed together
 * at authentication time in {@link LdapPasswordProvider} and {@link LdapPasswordProvider431}.
 *
 * Note: if the first provider supports account synchronization as part of its
 * {@link #checkPassword(String, String, boolean)} operation, it may require disabling to avoid
 * double-synching.
 *
 * Note: this implementation will require the OMERO LDAP configuration to be defined together
 * with the external configuration.
 *
 * @author seb
 *
 */
public class SynchronizingPasswordProviders implements PasswordProvider {

    /** Application logs. */
    private final Logger log = LoggerFactory.getLogger(SynchronizingPasswordProviders.class);

    /** First password provider in the chain (likely LDAP). */
    private final PasswordProvider primaryProvider;

    /** Fallback password provider (with account synchronization capabilities). */
    private final SynchronizingPasswordProvider synchronizingProvider;

    /**
     * Full constructor.
     *
     * @param primaryProvider the first provider (authentication only)
     * @param synchronizingProvider the second provider (authentication fallback + replication)
     */
    public SynchronizingPasswordProviders(
                    PasswordProvider primaryProvider,
                    SynchronizingPasswordProvider synchronizingProvider) {
        super();

        Check.notNull(primaryProvider, "primaryProvider");
        Check.notNull(synchronizingProvider, "synchronizingProvider");
        this.primaryProvider = primaryProvider;
        this.synchronizingProvider = synchronizingProvider;

        log.debug("[external_auth][chain] Initialized dual auth chain with providers: {} + {}",
                  primaryProvider.getClass().getSimpleName(),
                  synchronizingProvider.getClass().getSimpleName());
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public boolean hasPassword(String user) {
        boolean chainResult = false;

        // 1 - check primary (LDAP) provider
        boolean primaryResult = primaryProvider.hasPassword(user);

        // 2 - check external provider if needed
        if (!primaryResult) {
            chainResult = synchronizingProvider.hasPassword(user);
        }

        log.debug("[external_auth][chain] Chain hasPassword result: {} for user: {} [primary:{}]",
                  chainResult, user, primaryResult);

        return chainResult;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void changePassword(String user, String password) throws PasswordChangeException {
        // users should not update their passwords via OMERO as both providers are supposed
        // to be external to OMERO
        throw new PasswordChangeException(
            String.format("Account is managed by a third-party system [%s]", getClass().getSimpleName()));
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Boolean checkPassword(String user, String password, boolean readOnly) {
        Boolean chainResult = null;

        // 1 - check primary (LDAP) provider
        log.debug("[external_auth][chain] Chain step-1 - primary authentication for user: {}", user);
        Boolean primaryResult = primaryProvider.checkPassword(user, password, readOnly);

        // 2 - check external provider if needed
        Boolean externalResult = null;
        if (null == primaryResult) {

            log.debug("[external_auth][chain] Chain step-2 - secondary authentication for user: {}", user);
            // user not in primary source, try the external source
            externalResult = synchronizingProvider.checkPassword(user, password, readOnly);
            chainResult = externalResult;

        } else {

            // user found in primary/LDAP source, no need to check any further
            chainResult = primaryResult;

        }

        log.debug("[external_auth][chain] Chain authentication result: {} for user: {} [primary:{} - ext:{}]",
                  chainResult, user, primaryResult, externalResult);

        // 3 - regardless of the source used for authentication, synchronize against the external source
        // (provided the user is allowed to login)
        boolean isAuthSuccess = (null != chainResult && chainResult);
        if (isAuthSuccess) {

            log.debug("[external_auth][chain] Chain step-3 - external synchronization for user: {}", user);
            synchronizingProvider.synchronizeUser(user);

        }

        return chainResult;
    }

}