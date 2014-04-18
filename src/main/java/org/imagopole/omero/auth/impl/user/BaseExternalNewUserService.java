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

import ome.annotations.RolesAllowed;
import ome.api.ServiceInterface;
import ome.conditions.ApiUsageException;
import ome.conditions.ValidationException;
import ome.logic.AbstractLevel2Service;
import ome.logic.LdapImpl;
import ome.model.meta.Experimenter;
import ome.model.meta.ExperimenterGroup;
import ome.model.meta.GroupExperimenterMap;
import ome.parameters.Parameters;
import ome.security.auth.NewUserGroupBean;
import ome.security.auth.RoleProvider;
import ome.system.OmeroContext;
import ome.system.Roles;

import org.imagopole.omero.auth.api.ExternalAuthConfig;
import org.imagopole.omero.auth.api.user.ExternalNewUserService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.BeansException;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;

/**
 * Base {@link ExternalNewUserService} class - provides implementation inheritance of common
 * functionality and lifecycle for user creation from an external source.
 *
 * Most the API and implementation have been replicated and (slightly) amended from {@link LdapImpl}.
 * The main divergence points from the LDAP counterpart stem from:
 * - the ability for subclasses to define alternative groups memberships synchronisation behaviour
 * - the removal of unneeded LDAP parameters (eg. LDAP-specific groupspecs)
 * - the ability to optionally pre-seed the experimenter's LDAP DN for eventual fallback on {@link LdapImpl}
 *
 * @author seb
 *
 */
public abstract class BaseExternalNewUserService
       extends AbstractLevel2Service implements ExternalNewUserService, ApplicationContextAware {

    /** Application logs. */
    private final Logger log = LoggerFactory.getLogger(BaseExternalNewUserService.class);

    /** Configuration settings for the external accounts extension module. */
    protected final ExternalAuthConfig config;

    /** OMERO roles. */
    protected final Roles roles;

    /** OMERO roles service. */
    protected final RoleProvider roleProvider;

    /** OMERO Spring application context. */
    private OmeroContext appContext;

    /** Delimiter for configured group specs. */
    public static final String GROUPSPEC_DELIM = ":";

    /** Group spec for a spring bean - eg. <code> :bean:<beanName> </code>. */
    public static final String GROUPSPEC_BEAN = GROUPSPEC_DELIM + "bean" + GROUPSPEC_DELIM;

    /**
     * Full constructor.
     *
     * @param roles OMERO roles for superclass
     * @param config external extension configuration settings
     * @param roleProvider OMERO roles service
     */
    public BaseExternalNewUserService(
        Roles roles, ExternalAuthConfig config, RoleProvider roleProvider) {
        super();
        this.roles = roles;
        this.config = config;
        this.roleProvider = roleProvider;
    }

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
    * @see LdapImpl#synchronizeLdapUser(String)
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
    public boolean createUserFromExternalSource(String username, String password) {
        log.info("[external_auth] Preparing to create experimenter: {}", username);

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

            List<Long> groups = loadExternalGroups(username);

            if (null == groups || groups.isEmpty()) {
                throw new ValidationException(String.format("No group found for: %s", username));
            }

            // Create the unloaded groups for creation
            Long gid = groups.remove(0);
            ExperimenterGroup grp1 = new ExperimenterGroup(gid, false);
            Set<Long> otherGroupIds = new HashSet<Long>(groups);
            ExperimenterGroup grpOther[] = new ExperimenterGroup[otherGroupIds.size() + 1];

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
    public void synchronizeUserFromExternalSource(String username) {
        boolean syncOnLogin = config.isSyncOnLogin();
        log.debug("[external_auth] Synchronization enabled for attributes and memberships for user: {} ? {}",
                   username, syncOnLogin);

        if (!syncOnLogin) {
            return;
        }

        Experimenter omeExp = iQuery.findByString(Experimenter.class, "omeName", username);
        Experimenter externalExp = findExperimenterFromExternalSource(username);
        log.debug("[external_auth] looked up synchronization candidate {} - local: {} - remote: {}",
                  username, omeExp, externalExp);

        // difference from LdapImpl here: do not attempt to synchronize a user if it is
        // local to OMERO only, or not found in the remote data source
        boolean isUserOmeroOnly = (null == externalExp);
        if (isUserOmeroOnly) {
            log.info("[external_auth] username: {} unknown in external source - skipping sync (omero-only)", username);
            return;
        }

        List<Long> externalGroups = loadExternalGroups(username);

        List<Object[]> omeGroups = iQuery.projection(
                "select g.id from ExperimenterGroup g " +
                "join g.groupExperimenterMap m join m.child e where e.id = :id",
                new Parameters().addId(omeExp.getId()));

        Set<Long> omeGroupIds = new HashSet<Long>();
        for (Object[] objs : omeGroups) {
            omeGroupIds.add((Long) objs[0]);
        }

        // let the subclass decide on membership policy
        // eg. groups from external source take precedence, merge both datasets, etc.
        // TODO: have two separate options: sync user + sync group?
        synchronizeGroupsMemberships(
                        omeExp,
                        Collections.unmodifiableSet(omeGroupIds),
                        Collections.unmodifiableList(externalGroups));

        List<String> fields = Arrays.asList(
                Experimenter.FIRSTNAME,
                Experimenter.MIDDLENAME,
                Experimenter.LASTNAME,
                Experimenter.EMAIL,
                Experimenter.INSTITUTION);

        for (String field : fields) {
            String fieldname = field.substring(field.indexOf("_") + 1);
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
        iUpdate.flush();
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
     * @return the group identifiers for the user memberships
     *
     * @see LdapImpl#loadLdapGroups(String, org.springframework.ldap.core.DistinguishedName)
     */
    public List<Long> loadExternalGroups(String username) {
        final String grpSpec = config.getNewUserGroup();
        log.debug("[external_auth] loading externalNewUserGroup from spec: {}", grpSpec);

        final List<Long> groups = new ArrayList<Long>();
        if (null == grpSpec) {
            log.info("[external_auth] no externalNewUserGroup spec - skipping");

            return groups;
        }

        if (!grpSpec.startsWith(BaseExternalNewUserService.GROUPSPEC_BEAN)) {
            log.debug("[external_auth] Configuring externalNewUserGroup as literal value: {}", grpSpec);

            // The default case is the original logic: use the spec as name
            groups.add(roleProvider.createGroup(grpSpec, null, false));
            return groups; // EARLY EXIT!
        }

        final String data = grpSpec.substring(grpSpec.lastIndexOf(BaseExternalNewUserService.GROUPSPEC_DELIM) + 1);
        log.debug("[external_auth] Configuring externalNewUserGroup as javabean: {}", data);
        if (null == data || data.trim().isEmpty()) {
            throw new ValidationException(grpSpec + " spec currently not supported.");
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
     * Note: this method has been copied from {@link LdapImpl}, the only difference being the
     * introduction of <code>final<code> modifiers for all arguments.
     *
     * @param experimenter
     * @param base
     * @param minus
     * @param add
     */
    protected void modifyGroups(
                    final Experimenter experimenter,
                    final Collection<Long> base,
                    final Collection<Long> minus,
                    final boolean add) {

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
                log.debug("[external_auth] sizeOfGroupExperimenterMap=",
                          databaseExperimenter.sizeOfGroupExperimenterMap());

                if (databaseExperimenter.sizeOfGroupExperimenterMap() > 1) {
                    GroupExperimenterMap primary = databaseExperimenter.getGroupExperimenterMap(0);
                    GroupExperimenterMap next = databaseExperimenter.getGroupExperimenterMap(1);
                    log.debug("[external_auth] primary=", primary.parent().getId());
                    log.debug("[external_auth] next=", next.parent().getId());

                    if (primary.parent().getId().equals(roles.getUserGroupId())) {
                        log.debug("[external_auth] calling setDefaultGroup");
                        roleProvider.setDefaultGroup(experimenter, next.parent());
                    }
                }
            }
        }
    }

}
