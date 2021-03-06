/**
 *
 */
package org.imagopole.omero.auth.impl.user;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

import ome.annotations.RolesAllowed;
import ome.api.ServiceInterface;
import ome.conditions.ApiUsageException;
import ome.conditions.ValidationException;
import ome.logic.AbstractLevel2Service;
import ome.model.meta.Experimenter;
import ome.model.meta.ExperimenterGroup;
import ome.model.meta.GroupExperimenterMap;
import ome.parameters.Parameters;
import ome.security.auth.NewUserGroupBean;
import ome.security.auth.RoleProvider;
import ome.system.OmeroContext;
import ome.system.Roles;

import org.imagopole.omero.auth.api.ExternalAuthConfig;
import org.imagopole.omero.auth.api.ExternalServiceException;
import org.imagopole.omero.auth.api.user.ExternalNewUserService;
import org.imagopole.omero.auth.util.Check;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.BeansException;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;
import org.springframework.transaction.annotation.Transactional;

/**
 * Base {@link ExternalNewUserService} class - provides implementation inheritance of common
 * functionality and lifecycle for user creation from an external source.
 *
 * Most the API and implementation have been replicated and (slightly) amended from {@link ome.logic.LdapImpl}.
 * The main divergence points from the LDAP counterpart stem from:
 * - the ability for subclasses to define alternative groups memberships synchronisation behaviour
 * - the removal of unneeded LDAP parameters (eg. LDAP-specific groupspecs)
 * - the ability to optionally pre-seed the experimenter's LDAP DN for eventual fallback on {@link ome.logic.LdapImpl}
 *
 * @author seb
 *
 */
@Transactional
public abstract class BaseExternalNewUserService
       extends AbstractLevel2Service implements ExternalNewUserService, ApplicationContextAware {

    /** Application logs. */
    private final Logger log = LoggerFactory.getLogger(BaseExternalNewUserService.class);

    /** Configuration settings for the external accounts extension module. */
    private ExternalAuthConfig config;

    /** OMERO roles. */
    private Roles roles;

    /** OMERO roles service. */
    private RoleProvider roleProvider;

    /** OMERO Spring application context. */
    private OmeroContext appContext;

    /** Delimiter for configured group specs. */
    public static final String GROUPSPEC_DELIM = ":";

    /** Group spec for a spring bean - eg. <code> :bean:<beanName> </code>. */
    public static final String GROUPSPEC_BEAN = GROUPSPEC_DELIM + "bean" + GROUPSPEC_DELIM;

    /** List of experimenter fields to be synchronized on login. */
    public static final List<String> EXPERIMENTER_FIELD_NAMES = Arrays.asList(
                    Experimenter.FIRSTNAME,
                    Experimenter.MIDDLENAME,
                    Experimenter.LASTNAME,
                    Experimenter.EMAIL,
                    Experimenter.INSTITUTION);

    /** Delimiter for the experimenter's instance field names. */
    public static final String EXPERIMENTER_FIELD_DELIM = "_";

    /** Criteria query field for experimenter lookup by name on synchronization.
     * @see #synchronizeUserFromExternalSource(String) */
    private static final String OME_NAME = "omeName";

    /** HQL query to load the experimenter's groups on synchronization.
     *  @see #synchronizeUserFromExternalSource(String) */
    private static final String SELECT_GROUPS_IDS =
                    "select g.id "
                    + "from ExperimenterGroup g "
                    + "join g.groupExperimenterMap m "
                    + "join m.child e "
                    + "where e.id = :id";

    /**
     * {@inheritDoc}
     */
    @Override
    public Class<? extends ServiceInterface> getServiceInterface() {
        return ExternalNewUserService.class;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void setApplicationContext(ApplicationContext applicationContext) throws BeansException {
        appContext = (OmeroContext) applicationContext;
    }

   /**
    * Template method to allow subclasses to get a hook into the synchronization logic.
    *
    * Subclasses may add or remove memberships in the OMERO database based on their specific
    * replication policy (eg. considering a fully authoritative external source, merging to preserve
    * information local to OMERO, revoking memberships, etc.)
    *
    * @param omeroExperimenter the OMERO user
    * @param omeroGroups the groups the user belongs to in the OMERO database
    * @param externalGroups the groups the user belongs to in the external database
    *
    * @see ome.logic.LdapImpl#synchronizeLdapUser(String)
    */
    public abstract void synchronizeGroupsMemberships(
                   final Experimenter omeroExperimenter,
                   final Set<Long> omeroGroups,
                   final List<Long> externalGroups);

    /**
     * {@inheritDoc}
     */
    @Override
    @RolesAllowed("system")
    public boolean isEnabled() {
        boolean result = config.isEnabled();
        log.debug("[external_auth] config.is_enabled:{}", result);

        return result;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public boolean createUserFromExternalSource(String username, String password) throws ExternalServiceException {
        Check.notEmpty(username, "username");
        Check.notEmpty(password, "password");

        log.info("[external_auth] Preparing to create experimenter: {}", username);

        // double check user is not already present in OMERO
        Experimenter omeroExperimenter = iQuery.findByString(Experimenter.class, OME_NAME, username);
        if (null != omeroExperimenter) {
            throw new ValidationException(String.format("User already exists: %s", username));
        }

        Experimenter exp = findExperimenterFromExternalSource(username);

        // difference with Ldap version: LdapImpl performs this check in #mapUserName
        // this will cause the password provider to use the "default choice on create user"
        // (ie. return the configured value for "ignoreUnknown")
        if (null == exp) {
            throw new ApiUsageException(
                String.format("Cannot find user in external source: %s", username));
        }

        boolean access = validatePassword(username, password);
        log.info("[external_auth] Access granted for experimenter: {}? {}", username, access);

        if (access) {

            String grpSpec = config.getNewUserGroup();
            List<Long> groups = loadExternalGroups(username, grpSpec);

            if (null == groups || groups.isEmpty()) {
                throw new ValidationException(String.format("No group found for: %s", username));
            }

            // Create the unloaded groups for creation
            Long gid = groups.remove(0);
            ExperimenterGroup grp1 = new ExperimenterGroup(gid, false);
            Set<Long> otherGroupIds = new HashSet<Long>(groups);
            ExperimenterGroup[] grpOther = new ExperimenterGroup[otherGroupIds.size() + 1];

            int count = 0;
            for (Long id : otherGroupIds) {
                grpOther[count++] = new ExperimenterGroup(id, false);
            }
            grpOther[count] = new ExperimenterGroup(roles.getUserGroupId(), false);

            long uid = roleProvider.createExperimenter(exp, grp1, grpOther);
            log.info("[external_auth] Created experimenter with id: {} for username: {}", uid, username);

        }

        return access;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void synchronizeUserFromExternalSource(String username) throws ExternalServiceException {
        Check.notEmpty(username, "username");

        boolean syncGroupsOnLogin = config.syncGroupsOnLogin();
        boolean syncDefaultGroupOnLogin = config.syncDefaultGroupOnLogin();
        boolean syncUserOnLogin = config.syncUserOnLogin();
        log.debug("[external_auth] Synchronization settings for user:{} [groups:{}/{} - user:{}]",
                   username, syncGroupsOnLogin, syncDefaultGroupOnLogin, syncUserOnLogin);

        boolean noSyncOnLogin = !syncGroupsOnLogin && !syncDefaultGroupOnLogin && !syncUserOnLogin;
        if (noSyncOnLogin) {
            return;
        }

        Experimenter omeExp = iQuery.findByString(Experimenter.class, OME_NAME, username);

        // double check user is already present in OMERO
        boolean isUserMissingFromOmero = (null == omeExp);
        if (isUserMissingFromOmero) {
            throw new ValidationException(String.format("User unknown locally: %s", username));
        }

        Experimenter externalExp = findExperimenterFromExternalSource(username);
        log.debug("[external_auth] looked up synchronization candidate {} - remote: {} - local: {}",
                  username, externalExp, omeExp);

        // difference from LdapImpl here: do not attempt to synchronize a user if it is
        // local to OMERO only, or not found in the remote data source
        boolean isUserOmeroOnly = (null == externalExp);
        if (isUserOmeroOnly) {
            log.info("[external_auth] username: {} unknown in external source - skipping sync (omero-only)", username);
            return;
        }

        if (syncGroupsOnLogin) {

            String grpSpec = config.getNewUserGroup();
            List<Long> externalGroups = loadExternalGroups(username, grpSpec);

            List<Object[]> omeGroups = iQuery.projection(
                    SELECT_GROUPS_IDS,
                    new Parameters().addId(omeExp.getId()));

            Set<Long> omeGroupIds = new HashSet<Long>();
            for (Object[] objs : omeGroups) {
                omeGroupIds.add((Long) objs[0]);
            }

            // let the subclass decide on membership policy
            // eg. groups from external source take precedence, merge both datasets, etc.
            synchronizeGroupsMemberships(
                            omeExp,
                            Collections.unmodifiableSet(omeGroupIds),
                            Collections.unmodifiableList(externalGroups));

        }

        // also reset the default experimenter group's if configured accordingly
        if (syncDefaultGroupOnLogin) {

            String defaultGroupSpec = config.getDefaultGroup();
            String defaultGroupSyncPattern = config.getDefaultGroupPattern();

            synchronizeDefaultGroup(omeExp, defaultGroupSpec, defaultGroupSyncPattern);

        }

        if (syncUserOnLogin) {

            // provide a default implementation for user details synchronization
            synchronizeUserAttributes(username, omeExp, externalExp);

        }

        iUpdate.flush();
    }

    /**
     * Synchronize the experimenter's default group from the external source to OMERO.
     *
     * The default group is redefined conditionally: the current default group's name is matched
     * against the configured regex pattern before update, so as to avoid authoritatively overriding
     * the choice of user-defined default group on every login.
     *
     * @param experimenter the OMERO user
     * @param defaultGroupSpec the group spec to be used for default group definition
     * @param defaultGroupSyncPattern the pattern to be matched in order for the current default group to be overwritten
     * @throws ExternalServiceException in case of an underlying error during the remote service call
     */
    public void synchronizeDefaultGroup(
            final Experimenter experimenter,
            String defaultGroupSpec,
            String defaultGroupSyncPattern) throws ExternalServiceException {

        Check.notNull(experimenter, "experimenter");
        String username = experimenter.getOmeName();

        if (null == defaultGroupSyncPattern || defaultGroupSyncPattern.trim().isEmpty()) {
            log.warn("[external_auth] empty defaultGroup sync pattern - skipping");
            return;
        }

        try {
            Pattern.compile(defaultGroupSyncPattern);
        } catch (PatternSyntaxException pse) {
            log.error("[external_auth] invalid defaultGroup sync pattern - skipping", pse);
            return;
        }

        ExperimenterGroup experimenterDefaultGroup = getDefaultGroupOrNull(experimenter);
        if (null == experimenterDefaultGroup) {
            log.warn("[external_auth] no current defaultGroup for experimenter:{} - skipping", username);
            return;
        }

        String currentDefaultGroupName = experimenterDefaultGroup.getName();
        Long currentDefaultGroupId = experimenterDefaultGroup.getId();

        boolean shouldOverrideDefaultGroup =
            null != currentDefaultGroupName
            && currentDefaultGroupName.matches(defaultGroupSyncPattern);

        log.debug("[external_auth] Should override defaultGroup [{}-{}] for user:{}? {}",
                  currentDefaultGroupId, currentDefaultGroupName, username, shouldOverrideDefaultGroup);

        if (shouldOverrideDefaultGroup) {

            // let the group beans mechanism lookup and create the new default group
            List<Long> newDefaultGroups = loadExternalGroups(username, defaultGroupSpec);

            if (null != newDefaultGroups && !newDefaultGroups.isEmpty()) {

                // pick the first item in the list as the new default group
                Long defaultGroupId = newDefaultGroups.get(0);
                ExperimenterGroup newDefaultGroup = new ExperimenterGroup(defaultGroupId, false);

                log.info("[external_auth] Overriding defaultGroup to:{} for user:{} [was:{}-{}]",
                         defaultGroupId, username, currentDefaultGroupId, currentDefaultGroupName);

                // make sure the new default group is linked to the experimenter
                roleProvider.addGroups(experimenter, newDefaultGroup);

                // override the previous default group
                roleProvider.setDefaultGroup(experimenter, newDefaultGroup);

            }

        }

    }

    /**
     * Synchronize the experimenter's attributes from the external source to OMERO.
     *
     * The <code>omeExp</code> attributes are directly modified.
     *
     * Fields currently synchronized:
     * <ul>
     *   <li>{@link Experimenter.FIRSTNAME}</li>
     *   <li>{@link Experimenter.MIDDLENAME}</li>
     *   <li>{@link Experimenter.LASTNAME}</li>
     *   <li>{@link Experimenter.EMAIL}</li>
     *   <li>{@link Experimenter.INSTITUTION}</li>
     * </ul>
     *
     * @param username the experimenter's login
     * @param omeExp the OMERO user
     * @param externalExp the external user
     */
    public void synchronizeUserAttributes(
                    final String username,
                    final Experimenter omeExp,
                    final Experimenter externalExp) {

        Check.notNull(omeExp, "omeExp");
        Check.notNull(externalExp, "externalExp");

        for (String field : EXPERIMENTER_FIELD_NAMES) {
            String fieldname = field.substring(field.indexOf(EXPERIMENTER_FIELD_DELIM) + 1);
            String ome = (String) omeExp.retrieve(field);
            String ldap = (String) externalExp.retrieve(field);
            log.debug("[external_auth] Synchronizing field '{}' [{} -> {}]", fieldname, ldap, ome);

            if (ome == null) {
                if (ldap != null) {
                    log.debug("[external_auth] Setting {} for {}, to: {}", fieldname, username, ldap);
                    omeExp.putAt(field, ldap);
                }
            } else { //if (!ome.equals(ldap)) { // difference from LdapImpl here - prevent nulling an existing field
                if (ldap != null) {
                    log.debug("[external_auth] Changing {} for {}: {} -> {}", fieldname, username, ome, ldap);
                    omeExp.putAt(field, ldap);
                }
            }
        }
    }

    /**
     * Performs a two-step operation to lookup group memberships for a given user.
     *
     * Steps:
     * - inspect the OMERO configuration settings and load the appropriate group specification
     * - retrieve the groups from
     *
     * Depending on the configured setting, membership assignment may be static and local to OMERO
     * (ie. configured, instance-wide uniquedefault group name) or dynamic and loaded from a remote
     * source via a {@link NewUserGroupBean} invocation.
     * Groups will be created in the OMERO database if needed.
     *
     * @param username the OMERO username
     * @param grpSpec the group spec to be used for new groups definition
     * @return the group identifiers for the user memberships
     * @throws ExternalServiceException in case of an underlying error during the remote service call
     *
     * @see ome.logic.LdapImpl#loadLdapGroups(String, org.springframework.ldap.core.DistinguishedName)
     */
    public List<Long> loadExternalGroups(String username, String grpSpec) throws ExternalServiceException {
        Check.notEmpty(username, "username");

        log.debug("[external_auth] loading externalNewUserGroup from spec: {}", grpSpec);

        final List<Long> groups = new ArrayList<Long>();
        if (null == grpSpec) {
            log.info("[external_auth] no externalNewUserGroup spec - skipping");

            return groups;
        }

        if (!grpSpec.startsWith(GROUPSPEC_BEAN)) {
            log.debug("[external_auth] Configuring externalNewUserGroup as literal value: {}", grpSpec);

            // The default case is the original logic: use the spec as name
            groups.add(roleProvider.createGroup(grpSpec, null, false));
            return groups; // EARLY EXIT!
        }

        final String data = grpSpec.substring(grpSpec.lastIndexOf(GROUPSPEC_DELIM) + 1);
        log.debug("[external_auth] Configuring externalNewUserGroup as javabean: {}", data);
        if (null == data || data.trim().isEmpty()) {
            throw new ValidationException(String.format("%s spec currently not supported.", grpSpec));
        }

        //TODO: configure once at instantiation time rather than with every method invocation?
        NewUserGroupBean bean =
            (NewUserGroupBean) appContext.getBean(data, NewUserGroupBean.class);

        //note: nulled params for external GroupBeans: LdapConfig, LdapOperations, AttributeSet
        groups.addAll(bean.groups(username, null, null, roleProvider, null));
        log.debug("[external_auth] loaded {} external groups for user: {}", groups.size(), username);

        return groups;
    }

    /**
     * The ids in "minus" will be removed from the ids in "base" and then
     * the operation chosen by "add" will be run on them. This method
     * ignores all methods known by Roles.
     *
     * Note: this method has been copied from {@link ome.logic.LdapImpl}, the only difference being the
     * introduction of <code>final<code> modifiers for all arguments.
     *
     * @param experimenter
     * @param base
     * @param minus
     * @param add
     */
    public void modifyGroups(
                    final Experimenter experimenter,
                    final Collection<Long> base,
                    final Collection<Long> minus,
                    final boolean add) {

        Check.notNull(experimenter, "experimenter");
        Check.notNull(base, "base");
        Check.notNull(minus, "minus");

        log.debug("[external_auth] synchronizing groups for experimenter: {} - add={}", experimenter, add);
        log.debug("[external_auth] groups base: {}", base);
        log.debug("[external_auth] groups minus: {}", minus);

        Set<Long> ids = new HashSet<Long>(base);
        ids.removeAll(minus);
        // Take no actions on system/user group.
        ids.remove(roles.getSystemGroupId());
        ids.remove(roles.getUserGroupId());

        if (ids.size() > 0) {
            log.info("[external_auth] {} groups for {}: {}",
                     add ? "Adding" : "Removing", experimenter.getOmeName(), ids);

            Set<ExperimenterGroup> grps = new HashSet<ExperimenterGroup>();
            for (Long id : ids) {
                grps.add(new ExperimenterGroup(id, false));
            }

            if (add) {
                roleProvider.addGroups(experimenter, grps.toArray(new ExperimenterGroup[0]));
            } else {
                roleProvider.removeGroups(experimenter, grps.toArray(new ExperimenterGroup[0]));
            }

            if (add) {
                // If we have just added groups, then it's possible that
                // the "user" group is at the front of the list, in which
                // case we should assign another specific group.
                Experimenter databaseExperimenter = iQuery.get(Experimenter.class, experimenter.getId());
                log.debug("[external_auth] sizeOfGroupExperimenterMap={}",
                          databaseExperimenter.sizeOfGroupExperimenterMap());

                if (databaseExperimenter.sizeOfGroupExperimenterMap() > 1) {
                    GroupExperimenterMap primary = databaseExperimenter.getGroupExperimenterMap(0);
                    GroupExperimenterMap next = databaseExperimenter.getGroupExperimenterMap(1);
                    log.debug("[external_auth] primary={}", primary.parent().getId());
                    log.debug("[external_auth] next={}", next.parent().getId());

                    if (primary.parent().getId().equals(roles.getUserGroupId())) {
                        log.debug("[external_auth] calling setDefaultGroup");
                        roleProvider.setDefaultGroup(experimenter, next.parent());
                    }
                }
            }
        }
    }

    private ExperimenterGroup getDefaultGroupOrNull(final Experimenter experimenter) {
        Check.notNull(experimenter, "experimenter");

        ExperimenterGroup result = null;

        if (experimenter.sizeOfGroupExperimenterMap() > 0) {
            result = experimenter.getGroupExperimenterMap(0).parent();
        }

        return result;
    }

    /**
     * Returns config.
     * @return the config
     */
    public ExternalAuthConfig getConfig() {
        return config;
    }

    /**
     * Sets config.
     * @param config the config to set
     */
    public void setConfig(ExternalAuthConfig config) {
        this.config = config;
    }

    /**
     * Returns roles.
     * @return the roles
     */
    public Roles getRoles() {
        return roles;
    }

    /**
     * Sets roles.
     * @param roles the roles to set
     */
    public void setRoles(Roles roles) {
        this.roles = roles;
    }

    /**
     * Returns roleProvider.
     * @return the roleProvider
     */
    public RoleProvider getRoleProvider() {
        return roleProvider;
    }

    /**
     * Sets roleProvider.
     * @param roleProvider the roleProvider to set
     */
    public void setRoleProvider(RoleProvider roleProvider) {
        this.roleProvider = roleProvider;
    }

}
