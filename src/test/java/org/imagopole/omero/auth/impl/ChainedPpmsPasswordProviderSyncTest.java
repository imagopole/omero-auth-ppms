package org.imagopole.omero.auth.impl;

import static org.imagopole.omero.auth.TestsUtil.newFooUser;
import static org.imagopole.omero.auth.TestsUtil.newKnownUser;
import static org.imagopole.omero.auth.TestsUtil.newPpmsUser;
import static org.imagopole.omero.auth.TestsUtil.newSharedUser;
import static org.imagopole.omero.auth.TestsUtil.newSimpleUser;
import static org.imagopole.omero.auth.TestsUtil.wrangle;
import static org.imagopole.omero.auth.TestsUtil.wrangleFields;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertTrue;
import ome.model.meta.Experimenter;
import ome.security.auth.PasswordChangeException;

import org.imagopole.omero.auth.TestsUtil.Data;
import org.imagopole.omero.auth.TestsUtil.Groups;
import org.imagopole.omero.auth.TestsUtil.LdapUnit;
import org.imagopole.omero.auth.TestsUtil.OmeroUnit;
import org.imagopole.omero.auth.TestsUtil.PpmsUnit;
import org.imagopole.ppms.api.dto.PpmsUser;
import org.testng.annotations.Test;

public class ChainedPpmsPasswordProviderSyncTest extends AbstractChainedPpmsPasswordProviderTest {

    @Override
    protected void checkSetupConfig() {
        assertTrue(ldapConfig.isEnabled(), "Ldap config should be enabled");
        assertFalse(ldapConfig.isSyncOnLogin(), "Ldap config should not sync on login");

        assertTrue(ppmsConfig.isEnabled(), "Ppms config should be enabled");
        assertTrue(ppmsConfig.syncGroupsOnLogin(), "Ppms config should sync groups on login");
        assertTrue(ppmsConfig.syncUserOnLogin(), "Ppms config should sync user on login");
        // no dynamic sync on groups, use default group name
        assertEquals(ppmsConfig.getNewUserGroup(), PpmsUnit.DEFAULT_GROUP, "Ppms config bean incorrect");
    }

    @Test(groups = { Groups.INTEGRATION }, expectedExceptions = { PasswordChangeException.class })
    public void changePasswordShouldBeDisabled() throws PasswordChangeException {
        passwordProvider.changePassword(Data.USERNAME, Data.PASSWORD);
    }

    /** First login of a user known to LDAP only
     *
     *  The new {@link SynchronizingPasswordProviders} behaviour prevents LDAP-only users from
     *  logging in: to be "eligible" to password checking, they must exist in PPMS first.
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

    /** First login of a user known to PPMS only
     *
     *  If existing user - may be:
     *    - LDAP-enabled + PPMS
     *    - OMERO-local + PPMS
     **/
    @Test(groups = { Groups.INTEGRATION })
    public void loginPpmsAuthShouldCreateAccountIfNewUser() {
        String workDescription = "loginPpmsAuthShouldCreateAccountIfNewUser";

        // test precondition: check experimenter does not exists beforehand
        checkUserAbsent(PpmsUnit.DEFAULT_USER);

        PpmsUser ppmsUnitUser = newPpmsUser();
        ppmsUnitUser.setActive(true);

        pumapiClientMock.returns(ppmsUnitUser).getUser(PpmsUnit.DEFAULT_USER);
        pumapiClientMock.returns(true).authenticate(PpmsUnit.DEFAULT_USER, PpmsUnit.DEFAULT_PWD);

        checkLoginSuccess(PpmsUnit.DEFAULT_USER, PpmsUnit.DEFAULT_PWD, workDescription);

        // check experimenter fields
        Experimenter experimenter = iAdmin.lookupExperimenter(PpmsUnit.DEFAULT_USER);
        checkUserAttributes(experimenter,
                            PpmsUnit.DEFAULT_USER_GN, PpmsUnit.DEFAULT_USER_SN, PpmsUnit.DEFAULT_USER_EMAIL);

        // check the absence of LDAP password provider ownership
        checkLdapDnAbsent(PpmsUnit.DEFAULT_USER);

        // check default group membership (user created by PPMS user bean)
        checkMemberships(experimenter,
                         2, PpmsUnit.DEFAULT_GROUP, getRoles().getUserGroupName());

        // check invocations
        pumapiClientMock.assertInvoked().authenticate(PpmsUnit.DEFAULT_USER, PpmsUnit.DEFAULT_PWD);
    }

    /** First login of a user known to both LDAP and PPMS */
    @Test(groups = { Groups.INTEGRATION })
    public void loginPpmsLdapAuthShouldCreateAccountIfNewUser() {
        String workDescription = "loginPpmsLdapAuthShouldCreateAccountIfNewUser";

        // test precondition: check experimenter does not exists beforehand
        checkUserAbsent(LdapUnit.PPMS_USER);

        PpmsUser sharedUser = wrangleFields(newSharedUser());
        sharedUser.setActive(true);

        pumapiClientMock.returns(sharedUser).getUser(LdapUnit.PPMS_USER);
        pumapiClientMock.returns(true).authenticate(LdapUnit.PPMS_USER, LdapUnit.PPMS_PWD);

        checkLoginSuccess(LdapUnit.PPMS_USER, LdapUnit.PPMS_PWD, workDescription);

        // check experimenter fields
        Experimenter experimenter = iAdmin.lookupExperimenter(LdapUnit.PPMS_USER);
        checkUserAttributes(experimenter,
                            wrangle(LdapUnit.PPMS_USER_GN), wrangle(LdapUnit.PPMS_USER_SN),
                            wrangle(LdapUnit.PPMS_USER_EMAIL));

        // check LDAP password provider ownership
        checkLdapDnPresent(LdapUnit.PPMS_USER, LdapUnit.PPMS_USER_DN);

        // check default group membership
        checkMemberships(experimenter,
                         3, LdapUnit.DEFAULT_GROUP, getRoles().getUserGroupName(), PpmsUnit.DEFAULT_GROUP);

        // check invocations
        pumapiClientMock.assertNotInvoked().authenticate(LdapUnit.PPMS_USER, LdapUnit.PPMS_PWD);
    }

    /** First login of an existing user known to LDAP, PPMS and OMERO */
    @Test(groups = { Groups.INTEGRATION })
    public void loginPpmsLdapAuthShouldNotCreateAccountIfKnownUser() {
        String workDescription = "loginPpmsLdapAuthShouldNotCreateAccountIfKnownUser";

        // test precondition: check experimenter exists beforehand
        checkUserPresent(OmeroUnit.KNOWN_USER);

        // test precondition: check experimenter fields from DB
        Experimenter precondition = iAdmin.lookupExperimenter(OmeroUnit.KNOWN_USER);
        checkUserAttributes(precondition,
                            OmeroUnit.KNOWN_USER_GN, OmeroUnit.KNOWN_USER_SN, null);

        // test precondition: LDAP enabled
        checkLdapDnPresent(OmeroUnit.KNOWN_USER, OmeroUnit.KNOWN_USER_DN);

        PpmsUser knownUser = wrangleFields(newKnownUser());
        knownUser.setActive(true);

        pumapiClientMock.returns(knownUser).getUser(OmeroUnit.KNOWN_USER);
        pumapiClientMock.returns(true).authenticate(OmeroUnit.KNOWN_USER, OmeroUnit.KNOWN_PWD);

        checkLoginSuccess(OmeroUnit.KNOWN_USER, OmeroUnit.KNOWN_PWD, workDescription);

        // check experimenter fields
        Experimenter experimenter = iAdmin.lookupExperimenter(OmeroUnit.KNOWN_USER);
        checkUserAttributes(experimenter,
                            wrangle(OmeroUnit.KNOWN_USER_GN), wrangle(OmeroUnit.KNOWN_USER_SN),
                            wrangle(OmeroUnit.KNOWN_USER_EMAIL));

        // check default group membership
        checkMemberships(experimenter,
                         4,
                         OmeroUnit.DEFAULT_GROUP, getRoles().getUserGroupName(),
                         OmeroUnit.PPMS_DUPLICATE_GROUP, PpmsUnit.DEFAULT_GROUP);

        // check invocations
        pumapiClientMock.assertNotInvoked().authenticate(OmeroUnit.KNOWN_USER, OmeroUnit.KNOWN_PWD);
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
                            wrangle(PpmsUnit.OMERO_USER_GN), wrangle(PpmsUnit.OMERO_USER_SN),
                            wrangle(PpmsUnit.OMERO_USER_EMAIL));

        // check default group membership
        checkMemberships(experimenter,
                         3, OmeroUnit.DEFAULT_GROUP, getRoles().getUserGroupName(), PpmsUnit.DEFAULT_GROUP);

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
                         2, getRoles().getUserGroupName(), OmeroUnit.DEFAULT_GROUP);

        // check invocations
        pumapiClientMock.assertNotInvoked().authenticate(OmeroUnit.DEFAULT_USER, OmeroUnit.DEFAULT_PWD);
    }

}
