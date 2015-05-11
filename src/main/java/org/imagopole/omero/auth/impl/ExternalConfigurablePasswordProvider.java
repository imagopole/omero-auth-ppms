package org.imagopole.omero.auth.impl;

import java.util.List;

import ome.conditions.ApiUsageException;
import ome.model.meta.Experimenter;
import ome.security.auth.ConfigurablePasswordProvider;
import ome.security.auth.PasswordUtil;

import org.imagopole.omero.auth.api.ExternalAuthConfig;
import org.imagopole.omero.auth.api.ExternalServiceException;
import org.imagopole.omero.auth.api.SynchronizingPasswordProvider;
import org.imagopole.omero.auth.api.user.ExternalNewUserService;
import org.imagopole.omero.auth.util.Check;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * {@link ome.security.auth.PasswordProvider} which can create users and groups on
 * {@link #checkPassword(String, String) request} to synchronize with an external backend.
 *
 * This implementation has been largely inspired and carried over from {@link ome.security.auth.LdapPasswordProvider}
 * and {@link ome.security.auth.providers.LdapPasswordProvider431}, but delegates the actual account
 * synchronization tasks to a pluggable {@link ExternalNewUserService} (which emulates/customizes
 * the {@link ome.logic.LdapImpl} behaviour).
 *
 * This class hence mostly defines one possible account management lifecycle, with specific policies
 * for users and their group memberships being handled by {@link ExternalNewUserService} and
 * {@link org.imagopole.omero.auth.api.group.ExternalNewUserGroupBean} implementations, respectively.
 *
 * Additionally, user names belonging to "protected" (eg. OMERO system/internal) accounts may be
 * skipped by this provider - ie. {@link ExternalConfigurablePasswordProvider#hasPassword(String)}
 * will return false for all user names configured for exclusion.
 *
 * @author seb
 *
 * @see ome.security.auth.LdapPasswordProvider
 * @see ome.logic.LdapImpl
 * @see ExternalNewUserService
 * @see org.imagopole.omero.auth.api.group.ExternalNewUserGroupBean
 */

public class ExternalConfigurablePasswordProvider
       extends ConfigurablePasswordProvider implements SynchronizingPasswordProvider {

    /** Application logs. */
    private final Logger log = LoggerFactory.getLogger(ExternalConfigurablePasswordProvider.class);

    /** User management service for external accounts synchronization. */
    protected final ExternalNewUserService externalNewUserService;

    /** Configuration settings for the external accounts extension module. */
    protected final ExternalAuthConfig config;

    /**
     * Dependencies constructor.
     *
     * @param util OMERO password service
     * @param externalNewUserService OMERO + external source aware user management service
     * @param config external auth settings holder
     * @param ignoreUnknown as specified by {@link ConfigurablePasswordProvider}: "if true, should
     * return a null on {@link #checkPassword(String, String)} if the user is unknown, otherwise
     * a {@link Boolean#FALSE}. Default value: false"
     */
    public ExternalConfigurablePasswordProvider(
                    PasswordUtil util,
                    ExternalNewUserService externalNewUserService,
                    ExternalAuthConfig config,
                    boolean ignoreUnknown) {

        super(util, ignoreUnknown);

        Check.notNull(util, "util");
        Check.notNull(externalNewUserService, "externalNewUserService");
        Check.notNull(config, "config");

        this.externalNewUserService = externalNewUserService;
        this.config = config;

        log.info("[external_auth] ExternalNewUserService impl: {} [enabled:{} - ignoreUnknown:{} - isPwdRequired:{}]",
                 externalNewUserService.getClass().getSimpleName(),
                 externalNewUserService.isEnabled(),
                 ignoreUnknown,
                 util.isPasswordRequired(null));
    }

    /**
     * Default implementation for external password ownership checking.
     *
     * Currently mimicks behaviour implemented in {@link ome.security.auth.LdapPasswordProvider} and
     * {@link ome.security.auth.providers.LdapPasswordProvider431}, with the following differences:
     * - protected OMERO accounts (typically system users) are excluded
     * - unlike the LDAP password provider flavours, no information such as the user's DN
     *   is present in OMERO to indicate which provider is responsible for the password. Therefore
     *   the default is to return true if the user exists in both data stores (ie. OMERO and remote).
     *
     * Note: this checking might be improved if persisting {@link ome.model.meta.ExternalInfo}
     * part of the user's details. This would require:
     * - the external user source to provide numeric identifiers for users (and groups)
     * - possibly a custom {@link ome.security.auth.RoleProvider} implementation capable of handling
     *   deeper object copying so as to include external details.
     * - a custom hql query to detect the persisted entity's origin
     *
     * @param user the experimenter login
     * @see ome.security.auth.SimpleRoleProvider#copyUser
     * @see ome.security.auth.SimpleRoleProvider#copyGroup
     * @see ome.api.local.LocalUpdate#flush()
     * @see ome.api.IUpdate
     */
    @Override
    public boolean hasPassword(String user) {
        Check.notEmpty(user, "user");

        boolean result = false;

        if (externalNewUserService.isEnabled()) {
            Boolean hasUsername = hasUsername(user);
            boolean isUsernameFound = (null != hasUsername && hasUsername);

            if (isUsernameFound) {
                // similar logic to that of LdapPasswordProviders
                // as per javadoc: "this is typically only of importance during checkPassword,
                // [..] before a provider has not created a user, it is also not responsible."
                Long id = util.userId(user);
                log.debug("[external_auth] verifying local existence for user: {} - {}", user, id);

                if (null != id) {
                    result = true;
                }
            }

            log.debug("[external_auth] hasPassword result for username: {}:{} [{}]",
                      user, result, hasUsername);
        }

        return result;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Boolean hasUsername(String user) {
        Check.notEmpty(user, "user");

        Boolean result = null;

        if (externalNewUserService.isEnabled()) {
            log.debug("[external_auth] service enabled - verifying hasUsername status for user: {}", user);

            if (isProtectedAccount(user)) {
                log.trace("[external_auth] skipping protected OMERO account: {}", user);
                result = false;
            } else {
                try {
                    Experimenter externalUser = externalNewUserService.findExperimenterFromExternalSource(user);
                    result = (null != externalUser);
                } catch (ExternalServiceException ese) {
                    log.error("[external_auth] External service failure - fallback on hasUsername for: {}",
                              user, ese);
                }
            }
        }

        log.debug("[external_auth] hasUsername result for username: {}:{}", user, result);
        return result;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Boolean checkPassword(String user, String password, boolean readOnly) {
        Check.notEmpty(user, "user");
        Check.notEmpty(password, "password");

        if (!externalNewUserService.isEnabled()) {
            log.debug("[external_auth] ExternalNewUserService service not enabled - returning null password");
            return null; // EARLY EXIT!
        }

        // difference from LdapPasswordProvider431 but identical to LdapPasswordProvider: disable
        // all attempts to login with an empty password.
        if (password == null || password.trim().isEmpty()) {

            log.warn("[external_auth] Authentication rejected - Empty password for user: {}", user);
            loginAttempt(user, false);

            return false;

        }

        // difference from LdapPasswordProviders here: make sure that members of the
        // "protected" OMERO accounts (eg. root, guest) are not created or sync'd.
        // note: as per LoginAttemptMessage javadoc, "the success field  may be null in which case
        // the implementation did not know the user."
        boolean isProtectedAccount = isProtectedAccount(user);
        if (isProtectedAccount) {
            log.debug("[external_auth] Protected account - delegating authentication for user: {}", user);
            loginAttempt(user, null);

            return null;
        }

        // lookup OMERO user by name
        Long id = super.util.userId(user);

        // Unknown user. First try to create.
        if (null == id) {

            try {
                if (readOnly == true) {
                    throw new IllegalStateException("Cannot create user!");
                }

                log.debug("[external_auth] Attempting new user creation from remote source for username: {}", user);
                boolean login = externalNewUserService.createUserFromExternalSource(user, password);
                // Use default logic if the user creation did not exist,
                // because there may be another non-database login mechanism
                // which should also be given a chance.
                if (login) {
                    loginAttempt(user, true);
                    return true;
                }
            } catch (ApiUsageException e) {
                log.warn("[external_auth] Default choice on create user: {}", user, e);
            } catch (ExternalServiceException ese) {
                log.error("[external_auth] External service failure - fallback on create default for: {}",
                          user, ese);
            }

        }

        // Known user to OMERO
        else {

            try {
                log.debug("[external_auth] Verifying presence in remote source for: {}-{}", id, user);
                Experimenter externalUser = externalNewUserService.findExperimenterFromExternalSource(user);

                if (null != externalUser) {

                    log.debug("[external_auth] Attempting known user password check from remote source for: {}-{}", id, user);
                    return loginAttempt(user, externalNewUserService.validatePassword(user, password));

                } else {
                    // user not found in remote source
                    log.debug("[external_auth] User not in remote - skipping check from remote source for: {}-{}", id, user);
                }

            } catch (ApiUsageException e) {
                log.warn("[external_auth] Default choice on check external password: {}", user, e);
            } catch (ExternalServiceException ese) {
                log.error("[external_auth] External service failure - fallback on check default for: {}",
                          user, ese);
            }

        }

        // If anything goes wrong or no external user service is found in OMERO,
        // then use the default (configurable) logic, which will
        // probably return null in order to check JDBC for the password.
        // (or the next provider in the chain).
        log.info("[external_auth] Delegating password check logic for user: {}-{}", id, user);
        return super.checkPassword(user, password, readOnly);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void synchronizeUser(String username) {
        Check.notEmpty(username, "username");

        if (externalNewUserService.isEnabled()) {
            log.debug("[external_auth] Attempting synchronization from remote source for user: {}", username);
            try {
                externalNewUserService.synchronizeUserFromExternalSource(username);
            } catch (ExternalServiceException ese) {
                log.error("[external_auth] External service failure - fallback on sync for: {}",
                          username, ese);
            }
        }
    }

    private boolean isProtectedAccount(String username) {
        boolean result = false;

        List<String> excludedUsers = config.listExcludedUsers();
        if (null != excludedUsers) {

            result = excludedUsers.contains(username);
            log.debug("[external_auth] isProtectedAccount? {}:{}", username, result);

        }

        return result;
    }

}
