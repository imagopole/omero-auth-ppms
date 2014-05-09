package org.imagopole.omero.auth.impl;

import static org.imagopole.omero.auth.TestsUtil.activeSystem;
import static org.imagopole.omero.auth.TestsUtil.autonomousRights;
import static org.imagopole.omero.auth.TestsUtil.inactiveRights;
import static org.imagopole.omero.auth.TestsUtil.inactiveSystem;
import static org.imagopole.omero.auth.TestsUtil.newFooUser;
import static org.imagopole.omero.auth.TestsUtil.newKnownUser;
import static org.imagopole.omero.auth.TestsUtil.newOpenSystem;
import static org.imagopole.omero.auth.TestsUtil.newPpmsUser;
import static org.imagopole.omero.auth.TestsUtil.newRestrictedSystem;
import static org.imagopole.omero.auth.TestsUtil.newSharedUser;
import static org.imagopole.omero.auth.TestsUtil.newSharedUserB;
import static org.imagopole.omero.auth.TestsUtil.newSimpleUser;
import static org.imagopole.omero.auth.TestsUtil.noviceRights;
import static org.imagopole.omero.auth.TestsUtil.superUserRights;
import static org.imagopole.omero.auth.TestsUtil.systemName;
import static org.imagopole.omero.auth.TestsUtil.wrangleFields;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertTrue;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Properties;

import ome.model.meta.Experimenter;
import ome.security.auth.PasswordProvider;
import ome.system.OmeroContext;

import org.imagopole.omero.auth.TestsUtil.Env;
import org.imagopole.omero.auth.TestsUtil.Groups;
import org.imagopole.omero.auth.TestsUtil.LdapUnit;
import org.imagopole.omero.auth.TestsUtil.OmeroUnit;
import org.imagopole.omero.auth.TestsUtil.PpmsUnit;
import org.imagopole.ppms.api.dto.PpmsSystem;
import org.imagopole.ppms.api.dto.PpmsUser;
import org.imagopole.ppms.api.dto.PpmsUserPrivilege;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

public class ChainedPpmsPasswordProviderGroupBeanTest extends AbstractChainedPpmsPasswordProviderTest {

    /** @TestedObject */
    private PasswordProvider passwordProvider;

    @Override
    protected void setUpAfterServerStartup(OmeroContext omeroContext) {
        //-- test case services
        this.passwordProvider = (PasswordProvider) omeroContext.getBean("ppmsChainedPasswordProvider431");

        //-- OMERO server boilerplate
        super.setUpAfterServerStartup(omeroContext);
    }

    @Override
    protected PasswordProvider getPasswordProvider() {
        return this.passwordProvider;
    }

    @Override
    protected void setUpBeforeServerStartup(Properties systemProps) {
        // disable user synchronization only, keep groups sync on
        systemProps.put(Env.PPMS_SYNC_GROUPS, "true");
        systemProps.put(Env.PPMS_SYNC_USER, "false");

        // configure a group synchronization bean
        systemProps.put(Env.PPMS_NEW_USER_GROUP, PpmsUnit.AUTONOMY_GROUP_BEAN);

        // configure facilities and system types whitelists
        systemProps.put(Env.PPMS_INCLUDE_FACILITIES, PpmsUnit.FACILITIES_WHITELIST);
        systemProps.put(Env.PPMS_INCLUDE_SYSTEM_TYPES, PpmsUnit.SYSTEM_TYPES_WHITELIST);

        // startup server with overridden properties
        super.setUpBeforeServerStartup(systemProps);
    }

    @Override
    protected void checkSetupConfig() {
        assertTrue(ldapConfig.isEnabled(), "Ldap config should be enabled");
        assertFalse(ldapConfig.isSyncOnLogin(), "Ldap config should not sync on login");

        assertTrue(ppmsConfig.isEnabled(), "Ppms config should be enabled");
        assertTrue(ppmsConfig.syncGroupsOnLogin(), "Ppms config should sync groups on login");
        assertFalse(ppmsConfig.syncUserOnLogin(), "Ppms config should not sync user on login");
        // dynamic PPMS groups sync
        assertEquals(ppmsConfig.getNewUserGroup(), PpmsUnit.AUTONOMY_GROUP_BEAN, "Ppms config bean incorrect");
    }

    @DataProvider(name="insufficientRightsDataProvider")
    private Object[][] provideInsufficientSystemPrivileges() {
        return new Object[][] {
            { null                               },
            { Collections.emptyList()            },
            { inactiveRights(PpmsUnit.OPEN_SYSTEM_ID) },
            { noviceRights(PpmsUnit.OPEN_SYSTEM_ID)   }
        };
    }

    @DataProvider(name="grantedRightsDataProvider")
    private Object[][] provideGrantedSystemPrivileges() {
        return new Object[][] {
            { autonomousRights(PpmsUnit.OPEN_SYSTEM_ID) },
            { superUserRights(PpmsUnit.OPEN_SYSTEM_ID)  }
        };
    }

    /**
     * First login of a user known to LDAP only
     *
     * The new {@link SynchronizingPasswordProviders} behaviour prevents LDAP-only users from
     * logging in: to be "eligible" to password checking, they must exist in PPMS first.
     * */
    @Test(groups = { Groups.INTEGRATION })
    public void loginLdapAuthShouldNotCreateAccount() {
        String workDescription = "loginLdapAuthShouldNotCreateAccount";

        // test precondition: check experimenter does not exists beforehand
        checkUserAbsent(LdapUnit.DEFAULT_USER);

        // check authentication was not possible (user must be in both ppms + ldap, and is missing in OMERO)
        checkLoginNulled(LdapUnit.DEFAULT_USER, LdapUnit.DEFAULT_PWD, workDescription);

        // check the absence of experimenter
        checkUserAbsent(LdapUnit.DEFAULT_USER);

        // check invocations
        pumapiClientMock.assertNotInvoked().authenticate(LdapUnit.DEFAULT_USER, LdapUnit.DEFAULT_PWD);
    }

    /** First login of a user known to PPMS only, with no granted instrument
     *
     *  If existing user - may be:
     *    - LDAP-enabled + PPMS
     *    - OMERO-local + PPMS
     **/
    @Test(groups = { Groups.INTEGRATION }, dataProvider = "insufficientRightsDataProvider")
    public void loginPpmsAuthNoRightsShouldNotCreateAccount(List<PpmsUserPrivilege> userRights) {
        String workDescription = "loginPpmsAuthNoRightsShouldNotCreateAccount";

        // test precondition: check experimenter does not exists beforehand
        checkUserAbsent(PpmsUnit.DEFAULT_USER);

        PpmsUser ppmsUnitUser = newPpmsUser();
        ppmsUnitUser.setActive(true);

        pumapiClientMock.returns(ppmsUnitUser).getUser(PpmsUnit.DEFAULT_USER);
        pumapiClientMock.returns(true).authenticate(PpmsUnit.DEFAULT_USER, PpmsUnit.DEFAULT_PWD);

        pumapiClientMock.returns(userRights).getUserRights(PpmsUnit.DEFAULT_USER);

        // check authentication was not possible: no system granted => no group
        checkLoginNulled(PpmsUnit.DEFAULT_USER, PpmsUnit.DEFAULT_PWD, workDescription);

        // check the absence of experimenter (no group => failed creation)
        checkUserAbsent(PpmsUnit.DEFAULT_USER);

        // check invocations
        pumapiClientMock.assertInvoked().authenticate(PpmsUnit.DEFAULT_USER, PpmsUnit.DEFAULT_PWD);
        pumapiClientMock.assertInvoked().getUserRights(PpmsUnit.DEFAULT_USER);
        if (null == userRights || userRights.isEmpty()) {
            pumapiClientMock.assertNotInvoked().getSystem(PpmsUnit.OPEN_SYSTEM_ID);
        } else {
            pumapiClientMock.assertInvoked().getSystem(PpmsUnit.OPEN_SYSTEM_ID);
        }
    }

    /** First login of a user known to PPMS only, with one granted instrument
     *
     *  If existing user - may be:
     *    - LDAP-enabled + PPMS
     *    - OMERO-local + PPMS
     */
    @Test(groups = { Groups.INTEGRATION }, dataProvider = "grantedRightsDataProvider")
    public void loginPpmsAuthWithRightsShouldCreateAccount(List<PpmsUserPrivilege> userRights) {
        String workDescription = "loginPpmsAuthWithRightsShouldCreateAccount";

        // disable test precondition (dataPRovider)
        // checkUserAbsent(PpmsUnit.DEFAULT_USER);

        PpmsUser ppmsUnitUser = newPpmsUser();
        ppmsUnitUser.setActive(true);

        pumapiClientMock.returns(ppmsUnitUser).getUser(PpmsUnit.DEFAULT_USER);
        pumapiClientMock.returns(true).authenticate(PpmsUnit.DEFAULT_USER, PpmsUnit.DEFAULT_PWD);

        pumapiClientMock.returns(userRights).getUserRights(PpmsUnit.DEFAULT_USER);
        pumapiClientMock.returns(newOpenSystem()).getSystem(PpmsUnit.OPEN_SYSTEM_ID);

        checkLoginSuccess(PpmsUnit.DEFAULT_USER, PpmsUnit.DEFAULT_PWD, workDescription);

        checkLdapDnAbsent(PpmsUnit.DEFAULT_USER);

        // check granted memberships
        Experimenter experimenter = iAdmin.lookupExperimenter(PpmsUnit.DEFAULT_USER);
        checkMemberships(experimenter,
                         2, systemName(PpmsUnit.OPEN_SYSTEM_ID), getRoles().getUserGroupName());

        // check invocations
        pumapiClientMock.assertInvoked().authenticate(PpmsUnit.DEFAULT_USER, PpmsUnit.DEFAULT_PWD);
        pumapiClientMock.assertInvoked().getUserRights(PpmsUnit.DEFAULT_USER);
        pumapiClientMock.assertInvoked().getSystem(PpmsUnit.OPEN_SYSTEM_ID);
    }

    /** First login of a user known to both LDAP and PPMS, with one granted instrument on an
     *  "open system" (ie. which does not require autonomy). */
    @Test(groups = { Groups.INTEGRATION })
    public void loginPpmsLdapAuthShouldCreateAccountForNoviceOnOpenSystem() {
        String workDescription = "loginPpmsLdapAuthShouldCreateAccountForNoviceOnOpenSystem";

        // test precondition: check experimenter does not exists beforehand
        checkUserAbsent(LdapUnit.PPMS_USER);

        PpmsUser sharedUser = newSharedUser();
        sharedUser.setActive(true);

        pumapiClientMock.returns(sharedUser).getUser(LdapUnit.PPMS_USER);
        pumapiClientMock.returns(true).authenticate(LdapUnit.PPMS_USER, LdapUnit.PPMS_PWD);

        pumapiClientMock.returns(noviceRights(PpmsUnit.OPEN_SYSTEM_ID)).getUserRights(LdapUnit.PPMS_USER);
        pumapiClientMock.returns(newOpenSystem()).getSystem(PpmsUnit.OPEN_SYSTEM_ID);

        checkLoginSuccess(LdapUnit.PPMS_USER, LdapUnit.PPMS_PWD, workDescription);

        // check LDAP password provider ownership
        checkLdapDnPresent(LdapUnit.PPMS_USER, LdapUnit.PPMS_USER_DN);

        // check granted memberships
        Experimenter experimenter = iAdmin.lookupExperimenter(LdapUnit.PPMS_USER);

        checkMemberships(experimenter,
                         3, LdapUnit.DEFAULT_GROUP,
                         systemName(PpmsUnit.OPEN_SYSTEM_ID), getRoles().getUserGroupName());

        // check invocations
        pumapiClientMock.assertNotInvoked().authenticate(LdapUnit.PPMS_USER, LdapUnit.PPMS_PWD);
        pumapiClientMock.assertInvoked().getUserRights(LdapUnit.PPMS_USER);
        pumapiClientMock.assertInvoked().getSystem(PpmsUnit.OPEN_SYSTEM_ID);
    }

    /** First login of a user known to both LDAP and PPMS, with one granted instrument on a
     *  "restricted system" (ie. which does require autonomy). */
    @Test(groups = { Groups.INTEGRATION })
    public void loginPpmsLdapAuthShouldCreateAccountForNoviceOnRestrictedSystem() {
        String workDescription = "loginPpmsLdapAuthShouldCreateAccountForNoviceOnRestrictedSystem";

        // test precondition: check experimenter does not exists beforehand
        checkUserAbsent(LdapUnit.PPMS_USER_B);

        PpmsUser sharedUserB = newSharedUserB();
        sharedUserB.setActive(true);

        pumapiClientMock.returns(sharedUserB).getUser(LdapUnit.PPMS_USER_B);
        pumapiClientMock.returns(true).authenticate(LdapUnit.PPMS_USER_B, LdapUnit.PPMS_PWD);

        pumapiClientMock.returns(noviceRights(PpmsUnit.RESTRICTED_SYSTEM_ID)).getUserRights(LdapUnit.PPMS_USER_B);
        pumapiClientMock.returns(newRestrictedSystem()).getSystem(PpmsUnit.RESTRICTED_SYSTEM_ID);

        checkLoginSuccess(LdapUnit.PPMS_USER_B, LdapUnit.PPMS_PWD_B, workDescription);

        // check LDAP password provider ownership
        checkLdapDnPresent(LdapUnit.PPMS_USER_B, LdapUnit.PPMS_USER_DN_B);

        // check granted memberships
        Experimenter experimenter = iAdmin.lookupExperimenter(LdapUnit.PPMS_USER_B);

        checkMemberships(experimenter,
                         2, LdapUnit.DEFAULT_GROUP, getRoles().getUserGroupName());

        // check invocations
        pumapiClientMock.assertNotInvoked().authenticate(LdapUnit.PPMS_USER_B, LdapUnit.PPMS_PWD_B);
        pumapiClientMock.assertInvoked().getUserRights(LdapUnit.PPMS_USER_B);
        pumapiClientMock.assertInvoked().getSystem(PpmsUnit.RESTRICTED_SYSTEM_ID);
    }

    /** Sync login of an existing user known to LDAP, PPMS and OMERO, with multiple granted instruments
     *  and autonomy levels. */
    @Test(groups = { Groups.INTEGRATION })
    public void loginPpmsLdapAuthShouldIgnoreDuplicateGroupNames() {
        String workDescription = "loginPpmsLdapAuthShouldIgnoreDuplicateGroupNames";

        // test precondition: check experimenter exists beforehand
        checkUserPresent(OmeroUnit.KNOWN_USER);

        // test precondition: LDAP enabled
        checkLdapDnPresent(OmeroUnit.KNOWN_USER, OmeroUnit.KNOWN_USER_DN);

        PpmsUser knownUser = newKnownUser();
        knownUser.setActive(true);

        pumapiClientMock.returns(knownUser).getUser(OmeroUnit.KNOWN_USER);
        pumapiClientMock.returns(true).authenticate(OmeroUnit.KNOWN_USER, OmeroUnit.KNOWN_PWD);

        PpmsSystem duplicateGroupNameSystem =
            activeSystem(PpmsUnit.DUPLICATE_SYSTEM_ID, OmeroUnit.PPMS_DUPLICATE_GROUP);

        List<PpmsUserPrivilege> userRights = new ArrayList<PpmsUserPrivilege>();
        userRights.addAll(superUserRights(PpmsUnit.RESTRICTED_SYSTEM_ID));
        userRights.addAll(noviceRights(PpmsUnit.OPEN_SYSTEM_ID));
        userRights.addAll(autonomousRights(PpmsUnit.DUPLICATE_SYSTEM_ID));

        pumapiClientMock.returns(userRights).getUserRights(OmeroUnit.KNOWN_USER);
        pumapiClientMock.returns(newRestrictedSystem()).getSystem(PpmsUnit.RESTRICTED_SYSTEM_ID);
        pumapiClientMock.returns(newOpenSystem()).getSystem(PpmsUnit.OPEN_SYSTEM_ID);
        pumapiClientMock.returns(duplicateGroupNameSystem).getSystem(PpmsUnit.DUPLICATE_SYSTEM_ID);

        checkLoginSuccess(OmeroUnit.KNOWN_USER, OmeroUnit.KNOWN_PWD, workDescription);

        // check granted memberships
        Experimenter experimenter = iAdmin.lookupExperimenter(OmeroUnit.KNOWN_USER);

        checkMemberships(experimenter,
                         5,
                         OmeroUnit.DEFAULT_GROUP,
                         OmeroUnit.PPMS_DUPLICATE_GROUP,
                         systemName(PpmsUnit.OPEN_SYSTEM_ID),
                         systemName(PpmsUnit.RESTRICTED_SYSTEM_ID),
                         getRoles().getUserGroupName());

        // check invocations
        pumapiClientMock.assertNotInvoked().authenticate(OmeroUnit.KNOWN_USER, OmeroUnit.KNOWN_PWD);
        pumapiClientMock.assertInvoked().getUserRights(OmeroUnit.KNOWN_USER);
        pumapiClientMock.assertInvoked().getSystem(PpmsUnit.RESTRICTED_SYSTEM_ID);
        pumapiClientMock.assertInvoked().getSystem(PpmsUnit.OPEN_SYSTEM_ID);
        pumapiClientMock.assertInvoked().getSystem(PpmsUnit.DUPLICATE_SYSTEM_ID);
    }

    /** Sync login of an existing user known to PPMS and OMERO, but not LDAP,
     *  with inactive granted instruments. */
    @Test(groups = { Groups.INTEGRATION })
    public void loginPpmsLdapAuthShouldIgnoreInactiveGrantedSystems() {
        String workDescription = "loginPpmsLdapAuthShouldIgnoreInactiveGrantedSystems";

        // test precondition: check experimenter exists beforehand
        checkUserPresent(PpmsUnit.OMERO_USER);

        // test precondition: check existing memberships
        Experimenter precondition = iAdmin.lookupExperimenter(PpmsUnit.OMERO_USER);
        checkMemberships(precondition,
                         2, OmeroUnit.DEFAULT_GROUP, getRoles().getUserGroupName());

        PpmsUser knownUser = newKnownUser();
        knownUser.setActive(true);

        pumapiClientMock.returns(knownUser).getUser(PpmsUnit.OMERO_USER);
        pumapiClientMock.returns(true).authenticate(PpmsUnit.OMERO_USER, PpmsUnit.OMERO_PWD);

        PpmsSystem inactiveSystem =
            inactiveSystem(PpmsUnit.INACTIVE_SYSTEM_ID, systemName(PpmsUnit.INACTIVE_SYSTEM_ID));

        pumapiClientMock.returns(superUserRights(PpmsUnit.INACTIVE_SYSTEM_ID)).getUserRights(PpmsUnit.OMERO_USER);
        pumapiClientMock.returns(inactiveSystem).getSystem(PpmsUnit.INACTIVE_SYSTEM_ID);

        checkLoginSuccess(PpmsUnit.OMERO_USER, PpmsUnit.OMERO_PWD, workDescription);

        // check granted memberships (unchanged)
        Experimenter experimenter = iAdmin.lookupExperimenter(PpmsUnit.OMERO_USER);

        checkMemberships(experimenter,
                         2, OmeroUnit.DEFAULT_GROUP, getRoles().getUserGroupName());

        // check invocations
        pumapiClientMock.assertInvoked().authenticate(PpmsUnit.OMERO_USER, PpmsUnit.OMERO_PWD);
        pumapiClientMock.assertInvoked().getUserRights(PpmsUnit.OMERO_USER);
        pumapiClientMock.assertInvoked().getSystem(PpmsUnit.INACTIVE_SYSTEM_ID);
    }



    /** First login of an existing user known to PPMS and OMERO, but not LDAP */
    @Test(groups = { Groups.INTEGRATION })
    public void loginPpmsOmeroAuthShouldNotCreateAccountIfKnownUser() {
        String workDescription = "loginPpmsOmeroAuthShouldNotCreateAccountIfKnownUser";

        // test precondition: check experimenter exists beforehand
        checkUserPresent(PpmsUnit.OMERO_USER);

        // test precondition: LDAP disabled
        checkLdapDnAbsent(PpmsUnit.OMERO_USER);

        // test precondition: check experimenter fields from DB
        Experimenter precondition = iAdmin.lookupExperimenter(PpmsUnit.OMERO_USER);
        checkUserAttributes(precondition,
                            PpmsUnit.OMERO_USER_GN, PpmsUnit.OMERO_USER_SN, null);

        PpmsUser fooUser = wrangleFields(newFooUser());
        fooUser.setActive(true);

        pumapiClientMock.returns(fooUser).getUser(PpmsUnit.OMERO_USER);
        pumapiClientMock.returns(true).authenticate(PpmsUnit.OMERO_USER, PpmsUnit.OMERO_PWD);

        checkLoginSuccess(PpmsUnit.OMERO_USER, PpmsUnit.OMERO_PWD, workDescription);

        // check experimenter fields
        Experimenter experimenter = iAdmin.lookupExperimenter(PpmsUnit.OMERO_USER);
        checkUserAttributes(experimenter,
                            PpmsUnit.OMERO_USER_GN, PpmsUnit.OMERO_USER_SN, null);

        // check default group membership
        checkMemberships(experimenter,
                         2, OmeroUnit.DEFAULT_GROUP, getRoles().getUserGroupName());

        // check invocations
        pumapiClientMock.assertInvoked().authenticate(PpmsUnit.OMERO_USER, PpmsUnit.OMERO_PWD);
    }

    /** First login of an OMERO system ("protected") guest user */
    @Test(groups = { Groups.INTEGRATION })
    public void loginOmeroGuestAuthShouldNotCreateAccount() {
        String workDescription = "loginOmeroGuestAuthShouldNotCreateAccount";

        // no test precondition: guest always exists

        final String guestUser = getRoles().getGuestName();

        PpmsUser ppmsGuestUser = wrangleFields(newSimpleUser(guestUser, null));
        ppmsGuestUser.setActive(true);

        pumapiClientMock.returns(ppmsGuestUser).getUser(guestUser);
        pumapiClientMock.returns(true).authenticate(guestUser, OmeroUnit.GUEST_USER_PWD);

        checkLoginSuccess(guestUser, OmeroUnit.GUEST_USER_PWD, workDescription);

        // check experimenter fields
        Experimenter experimenter = iAdmin.lookupExperimenter(guestUser);
        checkUserAttributes(experimenter,
                            OmeroUnit.GUEST_USER_GN, OmeroUnit.GUEST_USER_SN, null);

        // check the absence of LDAP password provider ownership
        checkLdapDnAbsent(guestUser);

        // check default group membership
        checkMemberships(experimenter,
                         1, getRoles().getGuestGroupName());

        // check invocations
        pumapiClientMock.assertNotInvoked().authenticate(guestUser, OmeroUnit.GUEST_USER_PWD);
    }

    /** First login of an OMERO system ("protected") root user */
    @Test(groups = { Groups.INTEGRATION })
    public void loginOmeroRootAuthShouldNotCreateAccount() {
        String workDescription = "loginOmeroRootAuthShouldNotCreateAccount";

        // no test precondition: root always exists

        final String rootUser = getRoles().getRootName();

        PpmsUser ppmsRootUser = wrangleFields(newSimpleUser(rootUser, null));
        ppmsRootUser.setActive(true);

        pumapiClientMock.returns(ppmsRootUser).getUser(rootUser);
        pumapiClientMock.returns(true).authenticate(rootUser, OmeroUnit.ROOT_USER_PWD);

        checkLoginSuccess(rootUser, OmeroUnit.ROOT_USER_PWD, workDescription);

        // check experimenter fields
        Experimenter experimenter = iAdmin.lookupExperimenter(rootUser);
        checkUserAttributes(experimenter,
                            rootUser, rootUser, null);

        // check the absence of LDAP password provider ownership
        checkLdapDnAbsent(rootUser);

        // check default group membership
        checkMemberships(experimenter,
                         2, getRoles().getSystemGroupName(), getRoles().getUserGroupName());

        // check invocations
        pumapiClientMock.assertNotInvoked().authenticate(rootUser, OmeroUnit.ROOT_USER_PWD);
    }

    /** First login of an OMERO local user, unknown to both LDAP and PPMS */
    @Test(groups = { Groups.INTEGRATION })
    public void loginOmeroLocalAuthShouldNotCreateAccount() {
        String workDescription = "loginOmeroLocalAuthShouldNotCreateAccount";

        // test precondition: check experimenter exists beforehand
        checkUserPresent(OmeroUnit.DEFAULT_USER);

        pumapiClientMock.returns(null).getUser(OmeroUnit.DEFAULT_USER);

        checkLoginSuccess(OmeroUnit.DEFAULT_USER, OmeroUnit.DEFAULT_PWD, workDescription);

        // check experimenter has not been updated (no added membership)
        Experimenter experimenter = iAdmin.lookupExperimenter(OmeroUnit.DEFAULT_USER);

        checkMemberships(experimenter,
                         2, OmeroUnit.DEFAULT_GROUP, getRoles().getUserGroupName());

        // check invocations
        pumapiClientMock.assertNotInvoked().authenticate(OmeroUnit.DEFAULT_USER, OmeroUnit.DEFAULT_PWD);
    }

}
