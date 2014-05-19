package org.imagopole.omero.auth.impl.user;

import static org.imagopole.omero.auth.TestsUtil.activate;
import static org.imagopole.omero.auth.TestsUtil.newSharedUser;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertTrue;

import java.util.Properties;

import ome.conditions.ApiUsageException;
import ome.security.auth.PasswordProvider;
import ome.services.util.Executor;
import ome.system.OmeroContext;
import ome.system.ServiceFactory;

import org.imagopole.omero.auth.TestsUtil.Data;
import org.imagopole.omero.auth.TestsUtil.Env;
import org.imagopole.omero.auth.TestsUtil.LdapUnit;
import org.imagopole.omero.auth.TestsUtil.OmeroUnit;
import org.imagopole.omero.auth.TestsUtil.PpmsUnit;
import org.imagopole.omero.auth.api.user.ExternalNewUserService;
import org.imagopole.omero.auth.impl.AbstractPpmsOmeroIntegrationTest;
import org.imagopole.ppms.api.dto.PpmsUser;
import org.springframework.transaction.annotation.Transactional;
import org.testng.annotations.Test;

public class BaseExternalNewUserServiceTest extends AbstractPpmsOmeroIntegrationTest {

    /** @TestedObject */
    private ExternalNewUserService externalNewUserService;

    @Override
    protected void setUpBeforeServerStartup(Properties systemProps) {
        // configure a group synchronization bean
        systemProps.put(Env.PPMS_NEW_USER_GROUP, PpmsUnit.SYSTEM_GROUP_BEAN);

        //-- startup server with overridden properties
        super.setUpBeforeServerStartup(systemProps);
    }

    @Override
    protected void setUpAfterServerStartup(OmeroContext omeroContext) {
        //-- test case services
        this.externalNewUserService = (ExternalNewUserService) omeroContext.getBean("ppmsNewUserService");

        //-- OMERO server boilerplate
        super.setUpAfterServerStartup(omeroContext);
    }

    @Override
    protected void checkSetupConfig() {
        assertTrue(ppmsConfig.isEnabled(), "Ppms config should be enabled");
        assertTrue(ppmsConfig.syncGroupsOnLogin(), "Ppms config should sync groups on login");
        assertTrue(ppmsConfig.syncUserOnLogin(), "Ppms config should sync user on login");
        // dynamic PPMS groups sync
        assertEquals(ppmsConfig.getNewUserGroup(), PpmsUnit.SYSTEM_GROUP_BEAN, "Ppms config bean incorrect");
    }

    @Override
    protected PasswordProvider getPasswordProvider() {
        return null;
    }

    @Test(expectedExceptions = { ApiUsageException.class },
          expectedExceptionsMessageRegExp = "^Cannot find user in external source.*")
    public void createUserFromExternalSourceShouldFailOnRemoteUserNotFound() {
        String workDescription = "createUserFromExternalSourceShouldFailOnRemoteUserNotFound";

        pumapiClientMock.returns(null).getUser(Data.USERNAME);

        getExecutor().execute(getLoginPrincipal(), new Executor.SimpleWork(this, workDescription) {

            @Override
            @Transactional(readOnly = false)
            public Object doWork(org.hibernate.Session session, ServiceFactory serviceFactory) {
                boolean accessGranted = externalNewUserService.createUserFromExternalSource(Data.USERNAME, Data.PASSWORD);
                return accessGranted;
            }

        });

        checkUserAbsent(Data.USERNAME);

        // check invocations
        pumapiClientMock.assertInvoked().getUser(Data.USERNAME);
        pumapiClientMock.assertNotInvoked().authenticate(Data.USERNAME, Data.PASSWORD);
        pumapiClientMock.assertNotInvoked().getUserRights(Data.USERNAME);
    }

    @Test(expectedExceptions = { ApiUsageException.class },
          expectedExceptionsMessageRegExp = "^User already exists.*")
    public void createUserFromExternalSourceShouldFailOnDuplicateLocalUser() {
        String workDescription = "createUserFromExternalSourceShouldFailOnDuplicateLocalUser";

        // test precondition
        checkUserPresent(OmeroUnit.KNOWN_USER);

        pumapiClientMock.returns(null).getUser(OmeroUnit.KNOWN_USER);

        getExecutor().execute(getLoginPrincipal(), new Executor.SimpleWork(this, workDescription) {

            @Override
            @Transactional(readOnly = false)
            public Object doWork(org.hibernate.Session session, ServiceFactory serviceFactory) {
                boolean accessGranted = externalNewUserService.createUserFromExternalSource(OmeroUnit.KNOWN_USER, OmeroUnit.KNOWN_PWD);
                return accessGranted;
            }

        });

        // check invocations
        pumapiClientMock.assertNotInvoked().getUser(OmeroUnit.KNOWN_USER);
        pumapiClientMock.assertNotInvoked().authenticate(OmeroUnit.KNOWN_USER, OmeroUnit.KNOWN_PWD);
        pumapiClientMock.assertNotInvoked().getUserRights(OmeroUnit.KNOWN_USER);
    }

    @Test(expectedExceptions = { ApiUsageException.class },
          expectedExceptionsMessageRegExp = "^User unknown locally.*")
    public void synchronizeUserFromExternalSourceShouldFailOnLocalUserNotFound() {
        String workDescription = "synchronizeUserFromExternalSourceShouldFailOnLocalUserNotFound";

        PpmsUser sharedUser = activate(newSharedUser());

        pumapiClientMock.returns(sharedUser).getUser(LdapUnit.PPMS_USER);
        pumapiClientMock.returns(true).authenticate(LdapUnit.PPMS_USER, LdapUnit.PPMS_PWD);

        getExecutor().execute(getLoginPrincipal(), new Executor.SimpleWork(this, workDescription) {

            @Override
            @Transactional(readOnly = false)
            public Object doWork(org.hibernate.Session session, ServiceFactory serviceFactory) {
                externalNewUserService.synchronizeUserFromExternalSource(LdapUnit.PPMS_USER);
                return null;
            }

        });

        checkUserAbsent(LdapUnit.PPMS_USER);

        // check invocations
        pumapiClientMock.assertNotInvoked().getUser(LdapUnit.PPMS_USER);
        pumapiClientMock.assertNotInvoked().authenticate(LdapUnit.PPMS_USER, LdapUnit.PPMS_PWD);
        pumapiClientMock.assertNotInvoked().getUserRights(LdapUnit.PPMS_USER);
    }

    @Test
    public void synchronizeUserFromExternalSourceShouldSkipRemoteUserNotFound() {
        String workDescription = "synchronizeUserFromExternalSourceShouldSkipRemoteUserNotFound";

        pumapiClientMock.returns(null).getUser(OmeroUnit.KNOWN_USER);

        getExecutor().execute(getLoginPrincipal(), new Executor.SimpleWork(this, workDescription) {

            @Override
            @Transactional(readOnly = false)
            public Object doWork(org.hibernate.Session session, ServiceFactory serviceFactory) {
                externalNewUserService.synchronizeUserFromExternalSource(OmeroUnit.KNOWN_USER);
                return null;
            }

        });

        checkUserPresent(OmeroUnit.KNOWN_USER);

        // check invocations
        pumapiClientMock.assertInvoked().getUser(OmeroUnit.KNOWN_USER);
        pumapiClientMock.assertNotInvoked().authenticate(OmeroUnit.KNOWN_USER, OmeroUnit.KNOWN_PWD);
        pumapiClientMock.assertNotInvoked().getUserRights(OmeroUnit.KNOWN_USER);
    }

}
