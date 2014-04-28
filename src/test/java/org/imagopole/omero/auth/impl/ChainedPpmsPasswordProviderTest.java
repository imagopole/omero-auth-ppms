package org.imagopole.omero.auth.impl;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertNull;
import static org.testng.Assert.assertTrue;
import static org.testng.Assert.fail;

import java.util.List;

import ome.api.ILdap;
import ome.api.local.LocalAdmin;
import ome.conditions.ApiUsageException;
import ome.model.meta.Experimenter;
import ome.model.meta.ExperimenterGroup;
import ome.model.meta.Session;
import ome.security.auth.LdapConfig;
import ome.security.auth.PasswordChangeException;
import ome.security.auth.PasswordProvider;
import ome.services.util.Executor;
import ome.system.OmeroContext;
import ome.system.Principal;
import ome.system.ServiceFactory;

import org.imagopole.omero.auth.AbstractOmeroIntegrationTest;
import org.imagopole.omero.auth.TestsUtil;
import org.imagopole.omero.auth.TestsUtil.Data;
import org.imagopole.omero.auth.TestsUtil.Groups;
import org.imagopole.omero.auth.TestsUtil.LdapUnit;
import org.imagopole.omero.auth.TestsUtil.OmeroUnit;
import org.imagopole.omero.auth.TestsUtil.PpmsUnit;
import org.imagopole.omero.auth.api.ExternalAuthConfig;
import org.imagopole.omero.auth.impl.ppms.DefaultPpmsService;
import org.imagopole.ppms.api.PumapiClient;
import org.imagopole.ppms.api.dto.PpmsUser;
import org.springframework.transaction.annotation.Transactional;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.unitils.mock.Mock;
import org.unitils.mock.core.MockObject;

public class ChainedPpmsPasswordProviderTest extends AbstractOmeroIntegrationTest {

    /** @TestedObject */
    private PasswordProvider passwordProvider;

    private Mock<PumapiClient> pumapiClientMock;

    private LocalAdmin iAdmin;
    private ILdap iLdap;

    private ExternalAuthConfig ppmsConfig;
    private LdapConfig ldapConfig;

    @Override
    protected void setUpAfterServerStartup(OmeroContext omeroContext) {
        //-- OMERO server boilerplate
        super.setUpAfterServerStartup(omeroContext);

        //-- test case services
        this.passwordProvider = (PasswordProvider) omeroContext.getBean("ppmsChainedPasswordProvider");
        this.ppmsConfig = (ExternalAuthConfig) omeroContext.getBean("externalAuthConfiguration");
        this.ldapConfig = (LdapConfig) omeroContext.getBean("ldapConfig");

        iAdmin = (LocalAdmin) getServiceFactory().getAdminService();
        iLdap = getServiceFactory().getLdapService();

        // override the "remote" PPMS client from the spring context with a mock implementation
        pumapiClientMock = new MockObject<PumapiClient>(PumapiClient.class, null);
        DefaultPpmsService ppmsService = (DefaultPpmsService) omeroContext.getBean("ppmsService");
        ppmsService.setPpmsClient(pumapiClientMock.getMock());

        // make sure configuration is adequately setup to run this test
        checkSetupConfig();
    }

    /** Some sanity checks to assert the configuration expectations for the configuration settings. */
    private void checkSetupConfig() {
        assertTrue(ldapConfig.isEnabled(), "Ldap config should be enabled");
        assertFalse(ldapConfig.isSyncOnLogin(), "Ldap config should not sync on login");

        assertTrue(ppmsConfig.isEnabled(), "Ppms config should be enabled");
        assertTrue(ppmsConfig.syncGroupsOnLogin(), "Ppms config should sync groups on login");
        assertTrue(ppmsConfig.syncUserOnLogin(), "Ppms config should sync user on login");
        // no dynamic sync on groups, use default group name
        assertEquals(ppmsConfig.getNewUserGroup(), PpmsUnit.DEFAULT_GROUP, "Ppms config bean incorrect");
    }

    private void checkUserAbsent(String username) {
        String expectedExceptionMessage = "^No such experimenter: " + username;

        try {
            iAdmin.lookupExperimenter(username);

            fail("Should have thrown experimenter api usage exception");
        } catch(ApiUsageException e) {
            boolean passTest = e.getMessage().matches(expectedExceptionMessage);

            assertTrue(passTest, "Wrong api usage exception");
        }
    }

    private void checkUserPresent(String username) {
        Experimenter precondition = iAdmin.lookupExperimenter(username);
        assertNotNull(precondition, "Non null precondition expected");
    }

    private void checkLdapDnAbsent(String username) {
       String expectedExceptionMessage = "^Cannot find unique DistinguishedName: found=0";

       try {
           iLdap.findDN(username);

           fail("Should have thrown DN api usage exception");
       } catch(ApiUsageException e) {
           boolean passTest = e.getMessage().matches(expectedExceptionMessage);

           assertTrue(passTest, "Wrong api usage exception");
       }
    }

    private void checkUserAttributes(
                    Experimenter experimenter,
                    String expectedFirstName,
                    String expectedLastName,
                    String expectedEmail) {

        assertNotNull(experimenter, "Non null results expected");
        assertEquals(experimenter.getFirstName(), expectedFirstName, "Incorrect results");
        assertEquals(experimenter.getLastName(), expectedLastName, "Incorrect results");
        assertEquals(experimenter.getEmail(), expectedEmail, "Incorrect results");
    }

    private void checkMemberships(
                    Experimenter experimenter,
                    int expectedCount,
                    String... expectedNames) {

        List<ExperimenterGroup> memberships = experimenter.linkedExperimenterGroupList();
        assertNotNull(memberships, "Non null results expected");
        assertEquals(memberships.size(), expectedCount, "Incorrect memberships count");

        for (int i = 0; i < expectedNames.length; ++i) {
            String actualGroupName = memberships.get(i).getName();
            String expectedGroupName = expectedNames[i];

            assertEquals(actualGroupName, expectedGroupName, "Incorrect group");
        }
    }

    private Boolean doLogin(final String username, final String password, final String workDescription) {
       Boolean result = (Boolean) getExecutor().execute(getLoginPrincipal(), new Executor.SimpleWork(this, workDescription) {

           @Override
           @Transactional(readOnly = false)
           public Object doWork(org.hibernate.Session session, ServiceFactory serviceFactory) {
               Boolean result = passwordProvider.checkPassword(username, password, false);
               return result;
           }

       });

       return result;
    }

    @BeforeMethod
    public void createOmeroRootSession() {
        String userName = getRoles().getRootName();
        String groupName = getRoles().getSystemGroupName();
        String eventType = TestsUtil.TEST_EVENT_TYPE;
        String agentName = getClass().getSimpleName();

        Principal principal = new Principal(userName, groupName, eventType);
        Session omeroSession = getSessionManager().createWithAgent(principal, agentName);

        setLoginPrincipal(new Principal(omeroSession.getUuid(), groupName, eventType));
    }

    @AfterMethod
    public void closeAllOmeroSessions() {
        getSessionManager().closeAll();
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

        Boolean result = doLogin(LdapUnit.DEFAULT_USER, LdapUnit.DEFAULT_PWD, workDescription);

        // check authentication was not possible (user must be in both ppms + ldap, and is missing in OMERO)
        assertNull(result, "Null auth result expected");

        // check the absence of experimenter
        checkUserAbsent(LdapUnit.DEFAULT_USER);

        // check invocations
        pumapiClientMock.assertNotInvoked().authenticate(LdapUnit.DEFAULT_USER, LdapUnit.DEFAULT_PWD);
    }

    /** First login of a user known to PPMS only
     *
     *  If existing user - may be:
     *    - LDAP-enabled + PPMS => loginPpmsLdapAuthShouldNotCreateAccountIfKnownUser
     *    - OMERO-local + PPMS => loginPpmsOmeroAuthShouldNotCreateAccountIfKnownUser
     **/
    @Test(groups = { Groups.INTEGRATION })
    public void loginPpmsAuthShouldCreateAccountIfNewUser() {
        String workDescription = "loginPpmsAuthShouldCreateAccountIfNewUser";

        // test precondition: check experimenter does not exists beforehand
        checkUserAbsent(PpmsUnit.DEFAULT_USER);

        PpmsUser ppmsUnitUser = TestsUtil.newPpmsUser();
        ppmsUnitUser.setActive(true);

        pumapiClientMock.returns(ppmsUnitUser).getUser(PpmsUnit.DEFAULT_USER);
        pumapiClientMock.returns(true).authenticate(PpmsUnit.DEFAULT_USER, PpmsUnit.DEFAULT_PWD);

        Boolean result = doLogin(PpmsUnit.DEFAULT_USER, PpmsUnit.DEFAULT_PWD, workDescription);

        // check authentication succeeded
        assertNotNull(result, "Non null results expected");
        assertTrue(result, "Should auth ok");

        // check experimenter fields
        Experimenter experimenter = iAdmin.lookupExperimenter(PpmsUnit.DEFAULT_USER);
        checkUserAttributes(experimenter,
                            PpmsUnit.DEFAULT_USER_GN, PpmsUnit.DEFAULT_USER_SN, PpmsUnit.DEFAULT_USER_EMAIL);

        // check the absence of LDAP password provider ownership
        checkLdapDnAbsent(PpmsUnit.DEFAULT_USER);

        // check default group membership
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

        PpmsUser sharedUser = TestsUtil.newSharedUser();
        sharedUser.setActive(true);

        pumapiClientMock.returns(sharedUser).getUser(LdapUnit.PPMS_USER);
        pumapiClientMock.returns(true).authenticate(LdapUnit.PPMS_USER, LdapUnit.PPMS_PWD);

        Boolean result = doLogin(LdapUnit.PPMS_USER, LdapUnit.PPMS_PWD, workDescription);

        // check authentication succeeded
        assertNotNull(result, "Non null results expected");
        assertTrue(result, "Should auth ok");

        // check experimenter fields
        Experimenter experimenter = iAdmin.lookupExperimenter(LdapUnit.PPMS_USER);
        checkUserAttributes(experimenter,
                            LdapUnit.PPMS_USER_GN, LdapUnit.PPMS_USER_SN, LdapUnit.PPMS_USER_EMAIL);

        // check LDAP password provider ownership
        String dn = iLdap.findDN(LdapUnit.PPMS_USER);
        assertNotNull(dn, "Non null results expected");
        assertEquals(dn, LdapUnit.PPMS_USER_DN, "Incorrect results");

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

        // test precondition: LDAP enabled
        String dn = iLdap.findDN(OmeroUnit.KNOWN_USER);
        assertNotNull(dn, "Non null results expected");
        assertEquals(dn, OmeroUnit.KNOWN_USER_DN, "Incorrect results");

        PpmsUser knownUser = TestsUtil.newKnownUser();
        knownUser.setActive(true);

        pumapiClientMock.returns(knownUser).getUser(OmeroUnit.KNOWN_USER);
        pumapiClientMock.returns(true).authenticate(OmeroUnit.KNOWN_USER, OmeroUnit.KNOWN_PWD);

        Boolean result = doLogin(OmeroUnit.KNOWN_USER, OmeroUnit.KNOWN_PWD, workDescription);

        // check authentication succeeded
        assertNotNull(result, "Non null results expected");
        assertTrue(result, "Should auth ok");

        // check experimenter fields
        Experimenter experimenter = iAdmin.lookupExperimenter(OmeroUnit.KNOWN_USER);
        checkUserAttributes(experimenter,
                            OmeroUnit.KNOWN_USER_GN, OmeroUnit.KNOWN_USER_SN, OmeroUnit.KNOWN_USER_EMAIL);

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

        PpmsUser fooUser = TestsUtil.newFooUser();
        fooUser.setActive(true);

        pumapiClientMock.returns(fooUser).getUser(PpmsUnit.OMERO_USER);
        pumapiClientMock.returns(true).authenticate(PpmsUnit.OMERO_USER, PpmsUnit.OMERO_PWD);

        Boolean result = doLogin(PpmsUnit.OMERO_USER, PpmsUnit.OMERO_PWD, workDescription);

        // check authentication succeeded
        assertNotNull(result, "Non null results expected");
        assertTrue(result, "Should auth ok");

        // check experimenter fields
        Experimenter experimenter = iAdmin.lookupExperimenter(PpmsUnit.OMERO_USER);
        checkUserAttributes(experimenter,
                            PpmsUnit.OMERO_USER_GN, PpmsUnit.OMERO_USER_SN, PpmsUnit.OMERO_USER_EMAIL);

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

        pumapiClientMock.returns(null).getUser(guestUser);

        Boolean result = doLogin(guestUser, OmeroUnit.GUEST_USER_PWD, workDescription);

        // check authentication succeeded
        assertNotNull(result, "Non null results expected");
        assertTrue(result, "Should auth ok");

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

        pumapiClientMock.returns(null).getUser(rootUser);

        Boolean result = doLogin(rootUser, OmeroUnit.ROOT_USER_PWD, workDescription);

        // check authentication succeeded
        assertNotNull(result, "Non null results expected");
        assertTrue(result, "Should auth ok");

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

        Boolean result = doLogin(OmeroUnit.DEFAULT_USER, OmeroUnit.DEFAULT_PWD, workDescription);

        // check authentication succeeded (fallback on chained JDBC provider)
        assertNotNull(result, "Non null results expected");
        assertTrue(result, "Should auth ok");

        // check experimenter has not been updated (no added membership)
        Experimenter experimenter = iAdmin.lookupExperimenter(OmeroUnit.DEFAULT_USER);

        checkMemberships(experimenter,
                         2, getRoles().getUserGroupName(), OmeroUnit.DEFAULT_GROUP);

        // check invocations
        pumapiClientMock.assertNotInvoked().authenticate(OmeroUnit.DEFAULT_USER, OmeroUnit.DEFAULT_PWD);
    }

}
