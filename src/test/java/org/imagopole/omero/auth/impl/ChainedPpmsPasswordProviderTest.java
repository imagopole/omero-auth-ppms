package org.imagopole.omero.auth.impl;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertNotNull;
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
import ome.security.auth.PasswordProvider;
import ome.services.util.Executor;
import ome.system.OmeroContext;
import ome.system.Principal;
import ome.system.ServiceFactory;

import org.imagopole.omero.auth.AbstractOmeroIntegrationTest;
import org.imagopole.omero.auth.TestsUtil;
import org.imagopole.omero.auth.TestsUtil.LdapUnit;
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

    @Test
    public void checkPasswordLdapAuthShouldSaveDn() {
        String workDescription = "checkPasswordLdapAuthShouldSaveDn";

        Boolean result = (Boolean) getExecutor().execute(getLoginPrincipal(), new Executor.SimpleWork(this, workDescription) {

            @Override
            @Transactional(readOnly = false)
            public Object doWork(org.hibernate.Session session, ServiceFactory serviceFactory) {
                Boolean result = passwordProvider.checkPassword(LdapUnit.DEFAULT_USER, LdapUnit.DEFAULT_PWD, false);
                return result;
            }

        });

        // check authentication succeeded
        assertNotNull(result, "Non null results expected");
        assertTrue(result, "Should auth ok");

        // check experimenter fields
        Experimenter experimenter = iAdmin.lookupExperimenter(LdapUnit.DEFAULT_USER);
        assertNotNull(experimenter, "Non null results expected");
        assertEquals(experimenter.getFirstName(), LdapUnit.DEFAULT_USER_GN, "Incorrect results");
        assertEquals(experimenter.getLastName(), LdapUnit.DEFAULT_USER_SN, "Incorrect results");
        assertEquals(experimenter.getEmail(), LdapUnit.DEFAULT_USER_EMAIL, "Incorrect results");

        // check LDAP password provider ownership
        String dn = iLdap.findDN(LdapUnit.DEFAULT_USER);
        assertNotNull(dn, "Non null results expected");
        assertEquals(dn, LdapUnit.DEFAULT_USER_DN, "Incorrect results");

        // check default group membership
        List<ExperimenterGroup> memberships = experimenter.linkedExperimenterGroupList();
        assertNotNull(memberships, "Non null results expected");
        assertEquals(memberships.size(), 2, "Incorrect memberships count");
        assertEquals(memberships.get(0).getName(), LdapUnit.DEFAULT_GROUP, "Incorrect group");
        assertEquals(memberships.get(1).getName(), getRoles().getUserGroupName(), "Incorrect group");
    }

    @Test
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
        assertEquals(memberships.get(0).getName(), PpmsUnit.DEFAULT_GROUP, "Incorrect group");
        assertEquals(memberships.get(1).getName(), getRoles().getUserGroupName(), "Incorrect group");
    }

}
