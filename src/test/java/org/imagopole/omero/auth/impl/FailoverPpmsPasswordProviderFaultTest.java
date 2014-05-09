package org.imagopole.omero.auth.impl;

import static org.imagopole.omero.auth.TestsUtil.activeSystem;
import static org.imagopole.omero.auth.TestsUtil.autonomousRights;
import static org.imagopole.omero.auth.TestsUtil.newKnownUser;
import static org.imagopole.omero.auth.TestsUtil.newOpenSystem;
import static org.imagopole.omero.auth.TestsUtil.newPpmsUser;
import static org.imagopole.omero.auth.TestsUtil.newRestrictedSystem;
import static org.imagopole.omero.auth.TestsUtil.newSharedUser;
import static org.imagopole.omero.auth.TestsUtil.newSimpleUser;
import static org.imagopole.omero.auth.TestsUtil.noviceRights;
import static org.imagopole.omero.auth.TestsUtil.superUserRights;
import static org.imagopole.omero.auth.TestsUtil.wrangleFields;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertTrue;

import java.util.ArrayList;
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
import org.imagopole.ppms.api.PumapiException;
import org.imagopole.ppms.api.dto.PpmsSystem;
import org.imagopole.ppms.api.dto.PpmsUser;
import org.imagopole.ppms.api.dto.PpmsUserPrivilege;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

public class FailoverPpmsPasswordProviderFaultTest extends AbstractChainedPpmsPasswordProviderTest {

    /** @TestedObject */
    private PasswordProvider passwordProvider;

    @Override
    protected void setUpAfterServerStartup(OmeroContext omeroContext) {
        //-- test case services
        this.passwordProvider = (PasswordProvider) omeroContext.getBean("ppmsChainedFailoverPasswordProvider431");

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
     *
     * The LDAP failover allows creation in case of PPMS unavailability.
     * */
    @Test(groups = { Groups.INTEGRATION })
    public void loginLdapShouldNowAuthAndCreateAccountIfPpmsUnavailable() {
        String workDescription = "loginLdapShouldNowAuthAndCreateAccountIfPpmsUnavailable";

        // test precondition: check experimenter does not exists beforehand
        checkUserAbsent(LdapUnit.DEFAULT_USER);

        pumapiClientMock.raises(new PumapiException("ppms.failure/get-user")).getUser(LdapUnit.DEFAULT_USER);

        // check authentication was possible via LDAP failover
        checkLoginSuccess(LdapUnit.DEFAULT_USER, LdapUnit.DEFAULT_PWD, workDescription);

        // check LDAP password provider ownership
        checkLdapDnPresent(LdapUnit.PPMS_USER, LdapUnit.PPMS_USER_DN);

        // check the presence of experimenter with default group membership (should be LDAP default group only)
        Experimenter experimenter = iAdmin.lookupExperimenter(LdapUnit.DEFAULT_USER);
        checkMemberships(experimenter,
                         2, LdapUnit.DEFAULT_GROUP, getRoles().getUserGroupName());

        // check invocations
        pumapiClientMock.assertInvoked().getUser(LdapUnit.DEFAULT_USER);
        pumapiClientMock.assertNotInvoked().authenticate(LdapUnit.DEFAULT_USER, LdapUnit.DEFAULT_PWD);
    }

    /** First login of a user known to PPMS only, with one granted instrument
     *
     *  If existing user - may be:
     *    - LDAP-enabled + PPMS
     *    - OMERO-local + PPMS
     *
     *  No failover: login disabled for PPMS-only users.
     */
   @Test(groups = { Groups.INTEGRATION }, dataProvider = "grantedRightsDataProvider")
    public void loginPpmsWithRightsShouldNotAuthIfPpmsUnavailable(List<PpmsUserPrivilege> userRights) {
        String workDescription = "loginPpmsWithRightsShouldNotAuthIfPpmsUnavailable";

        // disable test precondition (dataPRovider)
        // checkUserAbsent(PpmsUnit.DEFAULT_USER);

        PpmsUser ppmsUnitUser = newPpmsUser();
        ppmsUnitUser.setActive(true);

        pumapiClientMock.returns(ppmsUnitUser).getUser(PpmsUnit.DEFAULT_USER);
        pumapiClientMock.returns(true).authenticate(PpmsUnit.DEFAULT_USER, PpmsUnit.DEFAULT_PWD);

        pumapiClientMock.raises(new PumapiException("ppms.failure/get-user-rights")).getUserRights(PpmsUnit.DEFAULT_USER);
        pumapiClientMock.returns(newOpenSystem()).getSystem(PpmsUnit.OPEN_SYSTEM_ID);

        checkLoginNulled(PpmsUnit.DEFAULT_USER, PpmsUnit.DEFAULT_PWD, workDescription);

        checkUserAbsent(PpmsUnit.DEFAULT_USER);

        // check invocations
        pumapiClientMock.assertInvoked().authenticate(PpmsUnit.DEFAULT_USER, PpmsUnit.DEFAULT_PWD);
        pumapiClientMock.assertInvoked().getUserRights(PpmsUnit.DEFAULT_USER);
        pumapiClientMock.assertNotInvoked().getSystem(PpmsUnit.OPEN_SYSTEM_ID);
    }

   /** First login of a user known to both LDAP and PPMS, with one granted instrument on an
    *  "open system" (ie. which does not require autonomy).
    *
    *  Chain "failover": sync disabled, primary LDAP provider auth. */
   @Test(groups = { Groups.INTEGRATION })
   public void loginPpmsLdapShouldSkipSyncIfPpmsUnavailable() {
       String workDescription = "loginPpmsLdapShouldSkipSyncIfPpmsUnavailable";

       // test precondition: check experimenter does not exists beforehand
       checkUserAbsent(LdapUnit.PPMS_USER);

       PpmsUser sharedUser = newSharedUser();
       sharedUser.setActive(true);

       pumapiClientMock.returns(sharedUser).getUser(LdapUnit.PPMS_USER);
       pumapiClientMock.returns(true).authenticate(LdapUnit.PPMS_USER, LdapUnit.PPMS_PWD);

       pumapiClientMock.returns(noviceRights(PpmsUnit.OPEN_SYSTEM_ID)).getUserRights(LdapUnit.PPMS_USER);
       pumapiClientMock.raises(new PumapiException("ppms.failure/get-system")).getSystem(PpmsUnit.OPEN_SYSTEM_ID);

       // check primary LDAP provider enables login
       checkLoginSuccess(LdapUnit.PPMS_USER, LdapUnit.PPMS_PWD, workDescription);

       // check LDAP password provider ownership
       checkLdapDnPresent(LdapUnit.PPMS_USER, LdapUnit.PPMS_USER_DN);

       // check granted memberships: should be restricted to LDAP default only (sync failure)
       Experimenter experimenter = iAdmin.lookupExperimenter(LdapUnit.PPMS_USER);

       checkMemberships(experimenter,
                        2, LdapUnit.DEFAULT_GROUP, getRoles().getUserGroupName());

       // check invocations
       pumapiClientMock.assertNotInvoked().authenticate(LdapUnit.PPMS_USER, LdapUnit.PPMS_PWD);
       pumapiClientMock.assertInvoked().getUserRights(LdapUnit.PPMS_USER);
       pumapiClientMock.assertInvoked().getSystem(PpmsUnit.OPEN_SYSTEM_ID);
   }

    /** Sync login of an existing user known to LDAP, PPMS and OMERO, with multiple granted instruments
     *  and autonomy levels.
     *
     *  LDAP failover for _all_ LDAP users. */
    @Test(groups = { Groups.INTEGRATION })
    public void loginPpmsLdapShouldNowPassAuthIfPpmsUnavailable() {
        String workDescription = "loginPpmsLdapShouldNowPassAuthIfPpmsUnavailable";

        // test precondition: check experimenter exists beforehand
        checkUserPresent(OmeroUnit.KNOWN_USER);

        // test precondition: LDAP enabled
        checkLdapDnPresent(OmeroUnit.KNOWN_USER, OmeroUnit.KNOWN_USER_DN);

        PpmsUser knownUser = newKnownUser();
        knownUser.setActive(true);

        pumapiClientMock.raises(new PumapiException("ppms.failure/get-user")).getUser(OmeroUnit.KNOWN_USER);
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

        // check default memberships only (sync failed)
        checkMemberships(experimenter,
                         3,
                         OmeroUnit.DEFAULT_GROUP,
                         OmeroUnit.PPMS_DUPLICATE_GROUP,
                         getRoles().getUserGroupName());

        // check invocations
        pumapiClientMock.assertNotInvoked().authenticate(OmeroUnit.KNOWN_USER, OmeroUnit.KNOWN_PWD);
        pumapiClientMock.assertNotInvoked().getUserRights(OmeroUnit.KNOWN_USER);
        pumapiClientMock.assertNotInvoked().getSystem(PpmsUnit.RESTRICTED_SYSTEM_ID);
        pumapiClientMock.assertNotInvoked().getSystem(PpmsUnit.OPEN_SYSTEM_ID);
        pumapiClientMock.assertNotInvoked().getSystem(PpmsUnit.DUPLICATE_SYSTEM_ID);
    }

    /** First login of an OMERO system ("protected") guest user
     *
     *  No failover: usual JDBC fallback. */
    @Test(groups = { Groups.INTEGRATION })
    public void loginOmeroGuestShouldAuthIfPpmsUnavailable() {
        String workDescription = "loginOmeroGuestShouldAuthIfPpmsUnavailable";

        // no test precondition: guest always exists

        final String guestUser = getRoles().getGuestName();

        PpmsUser ppmsGuestUser = newSimpleUser(guestUser, null);
        ppmsGuestUser.setActive(true);

        pumapiClientMock.raises(new PumapiException("ppms.failure/get-user")).getUser(guestUser);
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

    /** First login of an OMERO system ("protected") root user
     *
     *  No failover: usual JDBC fallback. */
    @Test(groups = { Groups.INTEGRATION })
    public void loginOmeroRootShouldAuthIfPpmsUnavailable() {
        String workDescription = "loginOmeroRootShouldAuthIfPpmsUnavailable";

        // no test precondition: root always exists

        final String rootUser = getRoles().getRootName();

        PpmsUser ppmsRootUser = wrangleFields(newSimpleUser(rootUser, null));
        ppmsRootUser.setActive(true);

        pumapiClientMock.raises(new PumapiException("ppms.failure/get-user")).getUser(rootUser);
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

    /** First login of an OMERO local user, unknown to both LDAP and PPMS
     *
     *  No failover: usual JDBC fallback. */
    @Test(groups = { Groups.INTEGRATION })
    public void loginOmeroLocalShouldAuthIfPpmsUnavailable() {
        String workDescription = "loginOmeroLocalShouldAuthIfPpmsUnavailable";

        // test precondition: check experimenter exists beforehand
        checkUserPresent(OmeroUnit.DEFAULT_USER);

        pumapiClientMock.raises(new PumapiException("ppms.failure/get-user")).getUser(OmeroUnit.DEFAULT_USER);

        checkLoginSuccess(OmeroUnit.DEFAULT_USER, OmeroUnit.DEFAULT_PWD, workDescription);

        // check experimenter has not been updated (no added membership)
        Experimenter experimenter = iAdmin.lookupExperimenter(OmeroUnit.DEFAULT_USER);

        checkMemberships(experimenter,
                         2, OmeroUnit.DEFAULT_GROUP, getRoles().getUserGroupName());

        // check invocations
        pumapiClientMock.assertNotInvoked().authenticate(OmeroUnit.DEFAULT_USER, OmeroUnit.DEFAULT_PWD);
    }

}
