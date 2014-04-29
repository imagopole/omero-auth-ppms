package org.imagopole.omero.auth.impl;

import static org.imagopole.omero.auth.TestsUtil.newFooUser;
import static org.imagopole.omero.auth.TestsUtil.newKnownUser;
import static org.imagopole.omero.auth.TestsUtil.newPpmsUser;
import static org.imagopole.omero.auth.TestsUtil.newSharedUser;
import static org.imagopole.omero.auth.TestsUtil.wrangleFields;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertTrue;

import java.util.Properties;

import ome.model.meta.Experimenter;

import org.imagopole.omero.auth.TestsUtil.Env;
import org.imagopole.omero.auth.TestsUtil.Groups;
import org.imagopole.omero.auth.TestsUtil.LdapUnit;
import org.imagopole.omero.auth.TestsUtil.OmeroUnit;
import org.imagopole.omero.auth.TestsUtil.PpmsUnit;
import org.imagopole.ppms.api.dto.PpmsUser;
import org.testng.annotations.Test;

public class ChainedPpmsPasswordProviderNoSyncTest extends AbstractChainedPpmsPasswordProviderTest {

    @Override
    protected void setUpBeforeServerStartup(Properties systemProps) {
        // disable all synchronization (groups + user)
        systemProps.put(Env.PPMS_SYNC_GROUPS, "false");
        systemProps.put(Env.PPMS_SYNC_USER, "false");

        // startup server with overridden properties
        super.setUpBeforeServerStartup(systemProps);
    }

    @Override
    protected void checkSetupConfig() {
        assertTrue(ldapConfig.isEnabled(), "Ldap config should be enabled");
        assertFalse(ldapConfig.isSyncOnLogin(), "Ldap config should not sync on login");

        assertTrue(ppmsConfig.isEnabled(), "Ppms config should be enabled");
        assertFalse(ppmsConfig.syncGroupsOnLogin(), "Ppms config should not sync groups on login");
        assertFalse(ppmsConfig.syncUserOnLogin(), "Ppms config should not sync user on login");
        // no dynamic sync on groups, use default group name
        assertEquals(ppmsConfig.getNewUserGroup(), PpmsUnit.DEFAULT_GROUP, "Ppms config bean incorrect");
    }

    /** First login of a user known to PPMS only
     *
     *  If existing user - may be:
     *    - LDAP-enabled + PPMS => loginPpmsLdapAuthShouldNotCreateAccountIfKnownUser
     *    - OMERO-local + PPMS => loginPpmsOmeroAuthShouldNotCreateAccountIfKnownUser
     **/
    @Test(groups = { Groups.INTEGRATION })
    public void loginPpmsAuthShouldKeepPpmsFields() {
        String workDescription = "loginPpmsAuthShouldKeepPpmsFields";

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

        // check unmodified group memberships (user created by PPMS user bean)
        checkMemberships(experimenter,
                         2, PpmsUnit.DEFAULT_GROUP, getRoles().getUserGroupName());

        // check invocations
        pumapiClientMock.assertInvoked().authenticate(PpmsUnit.DEFAULT_USER, PpmsUnit.DEFAULT_PWD);
    }

    /** First login of a user known to both LDAP and PPMS */
    @Test(groups = { Groups.INTEGRATION })
    public void loginPpmsLdapAuthShouldKeepLdapFields() {
        String workDescription = "loginPpmsLdapAuthShouldKeepLdapFields";

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
                            LdapUnit.PPMS_USER_GN, LdapUnit.PPMS_USER_SN, LdapUnit.PPMS_USER_EMAIL);

        // check default group membership (user created by LdapImpl)
        checkMemberships(experimenter,
                         2, LdapUnit.DEFAULT_GROUP, getRoles().getUserGroupName());

        // check invocations
        pumapiClientMock.assertNotInvoked().authenticate(LdapUnit.PPMS_USER, LdapUnit.PPMS_PWD);
    }

    /** First login of an existing user known to LDAP, PPMS and OMERO */
    @Test(groups = { Groups.INTEGRATION })
    public void loginPpmsLdapAuthShouldKeepOmeroFields() {
        String workDescription = "loginPpmsLdapAuthShouldKeepOmeroFields";

        // test precondition: check experimenter exists beforehand
        checkUserPresent(OmeroUnit.KNOWN_USER);

        // test precondition: LDAP enabled
        String dn = iLdap.findDN(OmeroUnit.KNOWN_USER);
        assertNotNull(dn, "Non null results expected");
        assertEquals(dn, OmeroUnit.KNOWN_USER_DN, "Incorrect results");

        PpmsUser knownUser = wrangleFields(newKnownUser());
        knownUser.setActive(true);

        pumapiClientMock.returns(knownUser).getUser(OmeroUnit.KNOWN_USER);
        pumapiClientMock.returns(true).authenticate(OmeroUnit.KNOWN_USER, OmeroUnit.KNOWN_PWD);

        checkLoginSuccess(OmeroUnit.KNOWN_USER, OmeroUnit.KNOWN_PWD, workDescription);

        // check experimenter fields (not sync'd)
        Experimenter experimenter = iAdmin.lookupExperimenter(OmeroUnit.KNOWN_USER);
        checkUserAttributes(experimenter,
                            OmeroUnit.KNOWN_USER_GN, OmeroUnit.KNOWN_USER_SN, null);

        // check default group membership
        checkMemberships(experimenter,
                         3,
                         OmeroUnit.DEFAULT_GROUP, OmeroUnit.PPMS_DUPLICATE_GROUP,
                         getRoles().getUserGroupName());

        // check invocations
        pumapiClientMock.assertNotInvoked().authenticate(OmeroUnit.KNOWN_USER, OmeroUnit.KNOWN_PWD);
    }

    /** First login of an existing user known to PPMS and OMERO, but not LDAP */
    @Test(groups = { Groups.INTEGRATION })
    public void loginPpmsOmeroAuthShouldKeepOmeroFields() {
        String workDescription = "loginPpmsOmeroAuthShouldKeepOmeroFields";

        // test precondition: check experimenter exists beforehand
        checkUserPresent(PpmsUnit.OMERO_USER);

        // test precondition: LDAP disabled
        checkLdapDnAbsent(PpmsUnit.OMERO_USER);

        PpmsUser fooUser = newFooUser();
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
    public void loginOmeroGuestAuthShouldKeepOmeroFields() {
        String workDescription = "loginOmeroGuestAuthShouldKeepOmeroFields";

        // no test precondition: guest always exists

        final String guestUser = getRoles().getGuestName();

        pumapiClientMock.returns(null).getUser(guestUser);

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
    public void loginOmeroRootAuthShouldKeepOmeroFields() {
        String workDescription = "loginOmeroRootAuthShouldKeepOmeroFields";

        // no test precondition: root always exists

        final String rootUser = getRoles().getRootName();

        pumapiClientMock.returns(null).getUser(rootUser);

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
    public void loginOmeroLocalAuthShouldKeepOmeroFields() {
        String workDescription = "loginOmeroLocalAuthShouldKeepOmeroFields";

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
