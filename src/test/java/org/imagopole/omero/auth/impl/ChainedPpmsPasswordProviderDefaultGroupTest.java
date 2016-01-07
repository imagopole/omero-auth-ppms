package org.imagopole.omero.auth.impl;

import static org.imagopole.omero.auth.TestsUtil.newKnownUser;
import static org.imagopole.omero.auth.TestsUtil.newOpenSystem;
import static org.imagopole.omero.auth.TestsUtil.newSharedUser;
import static org.imagopole.omero.auth.TestsUtil.noviceRights;
import static org.imagopole.omero.auth.TestsUtil.systemName;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertTrue;

import java.util.Properties;

import ome.model.meta.Experimenter;
import ome.security.auth.PasswordProvider;
import ome.system.OmeroContext;

import org.imagopole.omero.auth.TestsUtil.Env;
import org.imagopole.omero.auth.TestsUtil.Groups;
import org.imagopole.omero.auth.TestsUtil.LdapUnit;
import org.imagopole.omero.auth.TestsUtil.OmeroUnit;
import org.imagopole.omero.auth.TestsUtil.PpmsUnit;
import org.imagopole.ppms.api.dto.PpmsUser;
import org.testng.annotations.Test;

public class ChainedPpmsPasswordProviderDefaultGroupTest extends AbstractPpmsOmeroIntegrationTest {

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
        systemProps.put(Env.PPMS_SYNC_DEFAULT_GROUP, "true");
        systemProps.put(Env.PPMS_SYNC_USER, "false");

        // configure facilities and system types whitelists
        systemProps.put(Env.PPMS_INCLUDE_FACILITIES, PpmsUnit.FACILITIES_WHITELIST);
        systemProps.put(Env.PPMS_INCLUDE_SYSTEM_TYPES, PpmsUnit.SYSTEM_TYPES_WHITELIST);

        // configure a group synchronization bean
        systemProps.put(Env.PPMS_NEW_USER_GROUP, PpmsUnit.TRAINING_GROUP);

        // configure a default group synchronization bean
        systemProps.put(Env.PPMS_DEFAULT_GROUP, PpmsUnit.SYSTEM_GROUP_BEAN);
        systemProps.put(Env.PPMS_DEFAULT_GROUP_PATTERN, PpmsUnit.DEFAULT_GROUP_PATTERN);

        // startup server with overridden properties
        super.setUpBeforeServerStartup(systemProps);
    }

    @Override
    protected void checkSetupConfig() {
        assertTrue(ldapConfig.isEnabled(), "Ldap config should be enabled");
        assertFalse(ldapConfig.isSyncOnLogin(), "Ldap config should not sync on login");

        assertTrue(ppmsConfig.isEnabled(), "Ppms config should be enabled");
        assertTrue(ppmsConfig.syncGroupsOnLogin(), "Ppms config should sync groups on login");
        assertTrue(ppmsConfig.syncDefaultGroupOnLogin(), "Ppms config should sync default group on login");
        assertFalse(ppmsConfig.syncUserOnLogin(), "Ppms config should not sync user on login");
        // dynamic PPMS groups sync
        assertEquals(ppmsConfig.getNewUserGroup(), PpmsUnit.TRAINING_GROUP, "Ppms new group bean incorrect");
        assertEquals(ppmsConfig.getDefaultGroup(), PpmsUnit.SYSTEM_GROUP_BEAN, "Ppms default group bean incorrect");
        assertEquals(ppmsConfig.getDefaultGroupPattern(), PpmsUnit.DEFAULT_GROUP_PATTERN, "Ppms default group pattern incorrect");
    }

    /** First login of a user known to both LDAP and PPMS, with one granted instrument on an
     *  "open system" (ie. which does not require autonomy). */
    @Test(groups = { Groups.INTEGRATION })
    public void loginPpmsLdapAuthShouldOverrideMatchingDefaultGroupName() {
        String workDescription = "loginPpmsLdapAuthShouldOverrideMatchingDefaultGroupName";

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

        // check default group & granted memberships
        Experimenter experimenter = iAdmin.lookupExperimenter(LdapUnit.PPMS_USER);

        checkDefaultGroup(experimenter, systemName(PpmsUnit.OPEN_SYSTEM_ID));
        checkMemberships(experimenter,
                         4, LdapUnit.DEFAULT_GROUP,
                         systemName(PpmsUnit.OPEN_SYSTEM_ID),
                         PpmsUnit.TRAINING_GROUP, getRoles().getUserGroupName());

        // check invocations
        pumapiClientMock.assertNotInvoked().authenticate(LdapUnit.PPMS_USER, LdapUnit.PPMS_PWD);
        pumapiClientMock.assertInvoked().getSystem(PpmsUnit.OPEN_SYSTEM_ID);
    }

    /** Sync login of an existing user known to PPMS and OMERO, but not LDAP, with one granted instrument on an
     *  "open system" (ie. which does not require autonomy). */
    @Test(groups = { Groups.INTEGRATION })
    public void loginPpmsLdapAuthShouldIgnoreUnmatchedDefaultGroupNames() {
        String workDescription = "loginPpmsLdapAuthShouldIgnoreUnmatchedDefaultGroupNames";

        // test precondition: check experimenter exists beforehand
        checkUserPresent(PpmsUnit.OMERO_USER);

        // test precondition: check default group & existing memberships
        Experimenter precondition = iAdmin.lookupExperimenter(PpmsUnit.OMERO_USER);
        checkDefaultGroup(precondition, getRoles().getUserGroupName());
        checkMemberships(precondition,
                         2, OmeroUnit.DEFAULT_GROUP, getRoles().getUserGroupName());

        PpmsUser knownUser = newKnownUser();
        knownUser.setActive(true);

        pumapiClientMock.returns(knownUser).getUser(PpmsUnit.OMERO_USER);
        pumapiClientMock.returns(true).authenticate(PpmsUnit.OMERO_USER, PpmsUnit.OMERO_PWD);

        pumapiClientMock.returns(noviceRights(PpmsUnit.OPEN_SYSTEM_ID)).getUserRights(PpmsUnit.OMERO_USER);
        pumapiClientMock.returns(newOpenSystem()).getSystem(PpmsUnit.OPEN_SYSTEM_ID);

        checkLoginSuccess(PpmsUnit.OMERO_USER, PpmsUnit.OMERO_PWD, workDescription);

        // check default group & granted memberships (unchanged)
        Experimenter experimenter = iAdmin.lookupExperimenter(PpmsUnit.OMERO_USER);

        checkDefaultGroup(experimenter, OmeroUnit.DEFAULT_GROUP);
        checkMemberships(experimenter,
                         3, OmeroUnit.DEFAULT_GROUP, PpmsUnit.TRAINING_GROUP, getRoles().getUserGroupName());

        // check invocations
        pumapiClientMock.assertInvoked().authenticate(PpmsUnit.OMERO_USER, PpmsUnit.OMERO_PWD);
        pumapiClientMock.assertNotInvoked().getSystem(PpmsUnit.OPEN_SYSTEM_ID);
    }

}
