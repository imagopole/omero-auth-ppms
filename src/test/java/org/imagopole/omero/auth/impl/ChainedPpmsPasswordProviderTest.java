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

    private ExternalAuthConfig externalAuthConfig;
    private LdapConfig ldapConfig;

    @Override
    protected void setUpAfterServerStartup(OmeroContext omeroContext) {
        //-- OMERO server boilerplate
        super.setUpAfterServerStartup(omeroContext);

        //-- test case services
        this.passwordProvider = (PasswordProvider) omeroContext.getBean("ppmsChainedPasswordProvider");
        this.externalAuthConfig = (ExternalAuthConfig) omeroContext.getBean("externalAuthConfiguration");
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

        assertTrue(externalAuthConfig.isEnabled(), "Ppms config should be enabled");
        assertTrue(externalAuthConfig.isSyncOnLogin(), "Ppms config should sync on login");
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
     *  The new {@link SynchronizingPasswordProviders} behaviour prevents LDAP-only users from
     *  logging in: to be "eligible" to password checking, they must exist in PPMS first. */
    @Test(groups = { Groups.INTEGRATION })
    public void checkPasswordLdapAuthShouldBeIgnored() {
        String workDescription = "checkPasswordLdapAuthShouldBeIgnored";

        Boolean result = (Boolean) getExecutor().execute(getLoginPrincipal(), new Executor.SimpleWork(this, workDescription) {

            @Override
            @Transactional(readOnly = false)
            public Object doWork(org.hibernate.Session session, ServiceFactory serviceFactory) {
                Boolean result = passwordProvider.checkPassword(LdapUnit.DEFAULT_USER, LdapUnit.DEFAULT_PWD, false);
                return result;
            }

        });

        // check authentication succeeded
        assertNull(result, "Null auth result expected");

        // check the absence of experimenter
        try {
            iAdmin.lookupExperimenter(LdapUnit.DEFAULT_USER);

            fail("Should have thrown username api usage exception");
        } catch(ApiUsageException e) {
            boolean passTest = e.getMessage().matches("^No such experimenter: " + LdapUnit.DEFAULT_USER);
            assertTrue(passTest, "Wrong api usage exception");
        }

        // check invocations
        pumapiClientMock.assertNotInvoked().authenticate(LdapUnit.DEFAULT_USER, LdapUnit.DEFAULT_PWD);
    }

    /** First login of a user known to PPMS only */
    @Test(groups = { Groups.INTEGRATION })
    public void checkPasswordPpmsAuthShouldNotSaveDn() {
        String workDescription = "checkPasswordPpmsAuthShouldNotSaveDn";

        PpmsUser ppmsUnitUser = TestsUtil.newPpmsUser();
        ppmsUnitUser.setActive(true);

        pumapiClientMock.returns(ppmsUnitUser).getUser(PpmsUnit.DEFAULT_USER);
        pumapiClientMock.returns(true).authenticate(PpmsUnit.DEFAULT_USER, PpmsUnit.DEFAULT_PWD);

        Boolean result = (Boolean) getExecutor().execute(getLoginPrincipal(), new Executor.SimpleWork(this, workDescription) {

            @Override
            @Transactional(readOnly = false)
            public Object doWork(org.hibernate.Session session, ServiceFactory serviceFactory) {
                Boolean result = passwordProvider.checkPassword(PpmsUnit.DEFAULT_USER, PpmsUnit.DEFAULT_PWD, false);
                return result;
            }

        });

        // check authentication succeeded
        assertNotNull(result, "Non null results expected");
        assertTrue(result, "Should auth ok");

        // check experimenter fields
        Experimenter experimenter = iAdmin.lookupExperimenter(PpmsUnit.DEFAULT_USER);
        assertNotNull(experimenter, "Non null results expected");
        assertEquals(experimenter.getFirstName(), PpmsUnit.DEFAULT_USER_GN, "Incorrect results");
        assertEquals(experimenter.getLastName(), PpmsUnit.DEFAULT_USER_SN, "Incorrect results");
        assertEquals(experimenter.getEmail(), PpmsUnit.DEFAULT_USER_EMAIL, "Incorrect results");

        // check the absence of LDAP password provider ownership
        try {
            iLdap.findDN(PpmsUnit.DEFAULT_USER);

            fail("Should have thrown DN api usage exception");
        } catch(ApiUsageException e) {
            boolean passTest = e.getMessage().matches("^Cannot find unique DistinguishedName: found=0");
            assertTrue(passTest, "Wrong api usage exception");
        }

        // check default group membership
        List<ExperimenterGroup> memberships = experimenter.linkedExperimenterGroupList();
        assertNotNull(memberships, "Non null results expected");
        assertEquals(memberships.size(), 2, "Incorrect memberships count");
        assertEquals(memberships.get(0).getName(), PpmsUnit.DEFAULT_GROUP, "Incorrect ppms group");
        assertEquals(memberships.get(1).getName(), getRoles().getUserGroupName(), "Incorrect system group");

        // check invocations
        pumapiClientMock.assertInvoked().authenticate(PpmsUnit.DEFAULT_USER, PpmsUnit.DEFAULT_PWD);
    }

    /** First login of a user known to both LDAP and PPMS */
    @Test(groups = { Groups.INTEGRATION })
    public void checkPasswordBothAuthShouldSaveDn() {
        String workDescription = "checkPasswordBothAuthShouldSaveDn";

        PpmsUser sharedUser = TestsUtil.newSharedUser();
        sharedUser.setActive(true);

        pumapiClientMock.returns(sharedUser).getUser(LdapUnit.PPMS_USER);
        pumapiClientMock.returns(true).authenticate(LdapUnit.PPMS_USER, LdapUnit.PPMS_PWD);

        Boolean result = (Boolean) getExecutor().execute(getLoginPrincipal(), new Executor.SimpleWork(this, workDescription) {

            @Override
            @Transactional(readOnly = false)
            public Object doWork(org.hibernate.Session session, ServiceFactory serviceFactory) {
                Boolean result = passwordProvider.checkPassword(LdapUnit.PPMS_USER, LdapUnit.PPMS_PWD, false);
                return result;
            }

        });

        // check authentication succeeded
        assertNotNull(result, "Non null results expected");
        assertTrue(result, "Should auth ok");

        // check experimenter fields
        Experimenter experimenter = iAdmin.lookupExperimenter(LdapUnit.PPMS_USER);
        assertNotNull(experimenter, "Non null results expected");
        assertEquals(experimenter.getFirstName(), LdapUnit.PPMS_USER_GN, "Incorrect results");
        assertEquals(experimenter.getLastName(), LdapUnit.PPMS_USER_SN, "Incorrect results");
        assertEquals(experimenter.getEmail(), LdapUnit.PPMS_USER_EMAIL, "Incorrect results");

        // check LDAP password provider ownership
        String dn = iLdap.findDN(LdapUnit.PPMS_USER);
        assertNotNull(dn, "Non null results expected");
        assertEquals(dn, LdapUnit.PPMS_USER_DN, "Incorrect results");

        // check default group membership
        List<ExperimenterGroup> memberships = experimenter.linkedExperimenterGroupList();
        assertNotNull(memberships, "Non null results expected");
        assertEquals(memberships.size(), 3, "Incorrect memberships count");
        assertEquals(memberships.get(0).getName(), LdapUnit.DEFAULT_GROUP, "Incorrect ldap group");
        assertEquals(memberships.get(1).getName(), getRoles().getUserGroupName(), "Incorrect system group");
        assertEquals(memberships.get(2).getName(), PpmsUnit.DEFAULT_GROUP, "Incorrect ppm group");

        // check invocations
        pumapiClientMock.assertNotInvoked().authenticate(LdapUnit.PPMS_USER, LdapUnit.PPMS_PWD);
    }

    /** First login of an OMERO system ("protected") guest user */
    @Test(groups = { Groups.INTEGRATION })
    public void checkPasswordOmeroGuestAuthShouldNotSaveDn() {
        String workDescription = "checkPasswordOmeroSystemAuthShouldNotSaveDn";

        final String guestUser = getRoles().getGuestName();

        pumapiClientMock.returns(null).getUser(guestUser);

        Boolean result = (Boolean) getExecutor().execute(getLoginPrincipal(), new Executor.SimpleWork(this, workDescription) {

            @Override
            @Transactional(readOnly = false)
            public Object doWork(org.hibernate.Session session, ServiceFactory serviceFactory) {
                Boolean result = passwordProvider.checkPassword(guestUser, OmeroUnit.GUEST_USER_PWD, false);
                return result;
            }

        });

        // check authentication succeeded
        assertNotNull(result, "Non null results expected");
        assertTrue(result, "Should auth ok");

        // check experimenter fields
        Experimenter experimenter = iAdmin.lookupExperimenter(guestUser);
        assertNotNull(experimenter, "Non null results expected");
        assertEquals(experimenter.getFirstName(), OmeroUnit.GUEST_USER_GN, "Incorrect results");
        assertEquals(experimenter.getLastName(), OmeroUnit.GUEST_USER_SN, "Incorrect results");
        assertNull(experimenter.getEmail(), "Incorrect results");

        // check the absence of LDAP password provider ownership
        try {
            iLdap.findDN(guestUser);

            fail("Should have thrown DN api usage exception");
        } catch(ApiUsageException e) {
            boolean passTest = e.getMessage().matches("^Cannot find unique DistinguishedName: found=0");
            assertTrue(passTest, "Wrong api usage exception");
        }

        // check default group membership
        List<ExperimenterGroup> memberships = experimenter.linkedExperimenterGroupList();
        assertNotNull(memberships, "Non null results expected");
        assertEquals(memberships.size(), 1, "Incorrect memberships count");
        assertEquals(memberships.get(0).getName(), getRoles().getGuestGroupName(), "Incorrect guest group");

        // check invocations
        pumapiClientMock.assertNotInvoked().authenticate(guestUser, OmeroUnit.GUEST_USER_PWD);
    }

    /** First login of an OMERO system ("protected") root user */
    @Test(groups = { Groups.INTEGRATION })
    public void checkPasswordOmeroRootAuthShouldNotSaveDn() {
        String workDescription = "checkPasswordOmeroRootAuthShouldNotSaveDn";

        final String rootUser = getRoles().getRootName();

        pumapiClientMock.returns(null).getUser(rootUser);

        Boolean result = (Boolean) getExecutor().execute(getLoginPrincipal(), new Executor.SimpleWork(this, workDescription) {

            @Override
            @Transactional(readOnly = false)
            public Object doWork(org.hibernate.Session session, ServiceFactory serviceFactory) {
                Boolean result = passwordProvider.checkPassword(rootUser, OmeroUnit.ROOT_USER_PWD, false);
                return result;
            }

        });

        // check authentication succeeded
        assertNotNull(result, "Non null results expected");
        assertTrue(result, "Should auth ok");

        // check experimenter fields
        Experimenter experimenter = iAdmin.lookupExperimenter(rootUser);
        assertNotNull(experimenter, "Non null results expected");
        assertEquals(experimenter.getFirstName(), rootUser, "Incorrect results");
        assertEquals(experimenter.getLastName(), rootUser, "Incorrect results");
        assertNull(experimenter.getEmail(), "Incorrect results");

        // check the absence of LDAP password provider ownership
        try {
            iLdap.findDN(rootUser);

            fail("Should have thrown DN api usage exception");
        } catch(ApiUsageException e) {
            boolean passTest = e.getMessage().matches("^Cannot find unique DistinguishedName: found=0");
            assertTrue(passTest, "Wrong api usage exception");
        }

        // check default group membership
        List<ExperimenterGroup> memberships = experimenter.linkedExperimenterGroupList();
        assertNotNull(memberships, "Non null results expected");
        assertEquals(memberships.size(), 2, "Incorrect memberships count");
        assertEquals(memberships.get(0).getName(), getRoles().getSystemGroupName(), "Incorrect system/r group");
        assertEquals(memberships.get(1).getName(), getRoles().getUserGroupName(), "Incorrect system/u group");

        // check invocations
        pumapiClientMock.assertNotInvoked().authenticate(rootUser, OmeroUnit.ROOT_USER_PWD);
    }

}
