package org.imagopole.omero.auth.impl;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertNull;
import static org.testng.Assert.assertTrue;
import static org.testng.Assert.fail;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
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
import org.imagopole.omero.auth.api.ExternalAuthConfig;
import org.imagopole.omero.auth.impl.ppms.DefaultPpmsService;
import org.imagopole.ppms.api.PumapiClient;
import org.springframework.transaction.annotation.Transactional;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.unitils.mock.Mock;
import org.unitils.mock.core.MockObject;

public abstract class AbstractPpmsOmeroIntegrationTest extends AbstractOmeroIntegrationTest {

    protected Mock<PumapiClient> pumapiClientMock;

    protected LocalAdmin iAdmin;
    protected ILdap iLdap;

    protected ExternalAuthConfig ppmsConfig;
    protected LdapConfig ldapConfig;

    @Override
    protected void setUpAfterServerStartup(OmeroContext omeroContext) {
        //-- OMERO server boilerplate
        super.setUpAfterServerStartup(omeroContext);

        //-- test case services
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
    protected abstract void checkSetupConfig();

    /** Each subclass may test a different password provider flavor. */
    protected abstract PasswordProvider getPasswordProvider();

    protected void checkUserAbsent(String username) {
        String expectedExceptionMessage = "^No such experimenter: " + username;

        try {
            iAdmin.lookupExperimenter(username);

            fail("Should have thrown experimenter api usage exception");
        } catch(ApiUsageException e) {
            boolean passTest = e.getMessage().matches(expectedExceptionMessage);

            assertTrue(passTest, String.format("Wrong api usage exception: '%s' [pattern: '%s']",
                                               e.getMessage(), expectedExceptionMessage));
        }
    }

    protected void checkUserPresent(String username) {
        Experimenter precondition = iAdmin.lookupExperimenter(username);
        assertNotNull(precondition, "Non null precondition expected");
    }

    protected void checkLdapDnAbsent(String username) {
       String expectedExceptionMessage = "^Cannot find unique DistinguishedName: found=0";

       try {
           iLdap.findDN(username);

           fail("Should have thrown DN api usage exception");
       } catch(ApiUsageException e) {
           boolean passTest = e.getMessage().matches(expectedExceptionMessage);

           assertTrue(passTest, String.format("Wrong api usage exception: '%s' [pattern: '%s']",
                                              e.getMessage(), expectedExceptionMessage));
       }
    }

    protected void checkLdapDnPresent(String username, String expectedDn) {
        String dn = iLdap.findDN(username);
        assertNotNull(dn, "Non null results expected");
        assertEquals(dn, expectedDn, "Incorrect DN");
    }

    protected void checkUserAttributes(
                    Experimenter experimenter,
                    String expectedFirstName,
                    String expectedLastName,
                    String expectedEmail) {

        assertNotNull(experimenter, "Non null results expected");
        assertEquals(experimenter.getFirstName(), expectedFirstName, "Incorrect results");
        assertEquals(experimenter.getLastName(), expectedLastName, "Incorrect results");
        assertEquals(experimenter.getEmail(), expectedEmail, "Incorrect results");
    }

    protected void checkMemberships(
                    Experimenter experimenter,
                    int expectedCount,
                    String... expectedNames) {

        List<ExperimenterGroup> experimeterGroups = experimenter.linkedExperimenterGroupList();
        assertNotNull(experimeterGroups, "Non null results expected");

        List<ExperimenterGroup> memberships = new ArrayList<ExperimenterGroup>(experimeterGroups);
        assertEquals(memberships.size(), expectedCount, "Incorrect memberships count");

        // sort groups by name prior to names checks
        Collections.sort(memberships, new Comparator<ExperimenterGroup>() {

            @Override
            public int compare(ExperimenterGroup o1, ExperimenterGroup o2) {
                String name1 = o1.getName();
                String name2 = o2.getName();

                return name1.compareTo(name2);
            }

        });

        for (int i = 0; i < expectedNames.length; ++i) {
            String actualGroupName = memberships.get(i).getName();
            String expectedGroupName = expectedNames[i];

            assertEquals(actualGroupName, expectedGroupName, "Incorrect group");
        }
    }

    protected void checkLoginSuccess(final String username, final String password, final String workDescription) {
        Boolean result = doLogin(username, password, workDescription);

        // check authentication succeeded
        assertNotNull(result, "Non null results expected");
        assertTrue(result, "Should auth ok");
    }

    protected void checkLoginFailure(final String username, final String password, final String workDescription) {
        Boolean result = doLogin(username, password, workDescription);

        // check authentication failed
        assertNotNull(result, "Non null results expected");
        assertFalse(result, "Should auth ko");
    }

    protected void checkLoginNulled(final String username, final String password, final String workDescription) {
        Boolean result = doLogin(username, password, workDescription);

        // check authentication succeeded
        assertNull(result, "Null result expected - auth status unknown");
    }

    protected Boolean doLogin(final String username, final String password, final String workDescription) {
       Boolean result = (Boolean) getExecutor().execute(getLoginPrincipal(), new Executor.SimpleWork(this, workDescription) {

           @Override
           @Transactional(readOnly = false)
           public Object doWork(org.hibernate.Session session, ServiceFactory serviceFactory) {
               Boolean result = getPasswordProvider().checkPassword(username, password, false);
               return result;
           }

       });

       return result;
    }

    @BeforeMethod
    public void setupOmeroRootSession() {
        String userName = getRoles().getRootName();
        String groupName = getRoles().getSystemGroupName();
        String eventType = TestsUtil.TEST_EVENT_TYPE;
        String agentName = getClass().getSimpleName();
        String agentIp = TestsUtil.LOOPBACK_IPV4;

        Principal principal = new Principal(userName, groupName, eventType);
        Session omeroSession = getSessionManager().createWithAgent(principal, agentName, agentIp);

        setLoginPrincipal(new Principal(omeroSession.getUuid(), groupName, eventType));
    }

    @AfterMethod
    public void tearDownAllOmeroSessions() {
        getSessionManager().closeAll();
    }

}
