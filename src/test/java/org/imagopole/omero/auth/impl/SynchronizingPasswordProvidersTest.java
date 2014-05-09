package org.imagopole.omero.auth.impl;

import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertNull;
import static org.testng.Assert.assertTrue;
import ome.model.meta.Experimenter;
import ome.security.auth.PasswordUtil;
import ome.security.auth.providers.LdapPasswordProvider431;
import ome.system.OmeroContext;

import org.imagopole.omero.auth.TestsUtil.Data;
import org.imagopole.omero.auth.api.ExternalAuthConfig;
import org.imagopole.omero.auth.api.ExternalServiceException;
import org.imagopole.omero.auth.impl.ppms.user.PpmsExternalNewUserService;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.unitils.UnitilsTestNG;
import org.unitils.mock.Mock;
import org.unitils.mock.annotation.Dummy;
import org.unitils.mock.core.MockObject;

public class SynchronizingPasswordProvidersTest extends UnitilsTestNG {

    /** @TestedObject*/
    private SynchronizingPasswordProviders synchronizingProviders;

    /** Primary password provider */
    private Mock<LdapPasswordProvider431> ldapProviderMock;

    /** Secondary password provider (real instance with mock collaborators) */
    private ExternalConfigurablePasswordProvider ppmsPasswordProvider;

    /** Collaborator for secondary provider */
    private Mock<PpmsExternalNewUserService> ppmsNewUserServiceMock;

    @Dummy
    private Experimenter dummyUser;

    /** Always check password in RW mode.
     * @see SessionManagerImpl#executePasswordCheck(String, String) */
    private final boolean readOnly = false;

    @BeforeMethod
    public void setUp() {
        Mock<PasswordUtil> passwordUtilMock =
            new MockObject<PasswordUtil>(PasswordUtil.class, null);

        Mock<ExternalAuthConfig> externalConfigMock =
            new MockObject<ExternalAuthConfig>(ExternalAuthConfig.class, null);

        Mock<OmeroContext> omeroCtxMock = new MockObject<OmeroContext>(OmeroContext.class, null);

        ppmsPasswordProvider =
            new ExternalConfigurablePasswordProvider(
                            passwordUtilMock.getMock(),
                            ppmsNewUserServiceMock.getMock(),
                            externalConfigMock.getMock(),
                            true);

        ppmsPasswordProvider.setApplicationContext(omeroCtxMock.getMock());
        ldapProviderMock.getMock().setApplicationContext(omeroCtxMock.getMock());

        synchronizingProviders =
            new SynchronizingPasswordProviders(ldapProviderMock.getMock(), ppmsPasswordProvider);
    }

    @Test(expectedExceptions = { IllegalStateException.class },
          expectedExceptionsMessageRegExp = "^This provider is expected to executeCheckPasswordRW")
    public void chainShouldFailInReadOnlyMode() {
        synchronizingProviders.checkPassword(Data.USERNAME, Data.PASSWORD, true);
    }

    @Test
    public void chainShouldBeSkippedWhenSecondaryUnsynchronizable() {
        ldapProviderMock.returns(true).checkPassword(Data.USERNAME, Data.PASSWORD, readOnly);
        ppmsNewUserServiceMock.returns(true).isEnabled();
        ppmsNewUserServiceMock.returns(null).findExperimenterFromExternalSource(Data.USERNAME);

        Boolean result = synchronizingProviders.checkPassword(Data.USERNAME, Data.PASSWORD, readOnly);
        assertNull(result, "Null result expected");

        ppmsNewUserServiceMock.assertNotInvoked().validatePassword(Data.USERNAME, Data.PASSWORD);
        ppmsNewUserServiceMock.assertInvoked().findExperimenterFromExternalSource(Data.USERNAME);
        ppmsNewUserServiceMock.assertNotInvoked().synchronizeUserFromExternalSource(Data.USERNAME);
        ldapProviderMock.assertNotInvoked().checkPassword(Data.USERNAME, Data.PASSWORD, readOnly);
    }

    @Test
    public void chainShouldBeSkippedWhenSecondaryDisabled() {
        ldapProviderMock.returns(true).checkPassword(Data.USERNAME, Data.PASSWORD, readOnly);
        ppmsNewUserServiceMock.returns(false).isEnabled();
        ppmsNewUserServiceMock.returns(dummyUser).findExperimenterFromExternalSource(Data.USERNAME);

        Boolean result = synchronizingProviders.checkPassword(Data.USERNAME, Data.PASSWORD, readOnly);
        assertNull(result, "Null result expected");

        ppmsNewUserServiceMock.assertNotInvoked().validatePassword(Data.USERNAME, Data.PASSWORD);
        ppmsNewUserServiceMock.assertNotInvoked().findExperimenterFromExternalSource(Data.USERNAME);
        ppmsNewUserServiceMock.assertNotInvoked().synchronizeUserFromExternalSource(Data.USERNAME);
        ldapProviderMock.assertNotInvoked().checkPassword(Data.USERNAME, Data.PASSWORD, readOnly);
    }

    @Test
    public void chainShouldBeSkippedWhenSecondaryUnavailable() {
        ldapProviderMock.returns(true).checkPassword(Data.USERNAME, Data.PASSWORD, readOnly);
        ppmsNewUserServiceMock.returns(true).isEnabled();
        ppmsNewUserServiceMock.raises(ExternalServiceException.class).findExperimenterFromExternalSource(Data.USERNAME);

        Boolean result = synchronizingProviders.checkPassword(Data.USERNAME, Data.PASSWORD, readOnly);
        assertNull(result, "Null result expected");

        ppmsNewUserServiceMock.assertNotInvoked().validatePassword(Data.USERNAME, Data.PASSWORD);
        ppmsNewUserServiceMock.assertInvoked().findExperimenterFromExternalSource(Data.USERNAME);
        ppmsNewUserServiceMock.assertNotInvoked().synchronizeUserFromExternalSource(Data.USERNAME);
        ldapProviderMock.assertNotInvoked().checkPassword(Data.USERNAME, Data.PASSWORD, readOnly);
    }

    @Test
    public void secondaryProviderShouldCheckAuthWhenUserPrimarySuceeds() {
        ldapProviderMock.returns(true).checkPassword(Data.USERNAME, Data.PASSWORD, readOnly);
        ppmsNewUserServiceMock.returns(true).isEnabled();
        ppmsNewUserServiceMock.returns(dummyUser).findExperimenterFromExternalSource(Data.USERNAME);

        Boolean result = synchronizingProviders.checkPassword(Data.USERNAME, Data.PASSWORD, readOnly);
        assertNotNull(result, "Non-null result expected");
        assertTrue(result, "Incorrect result");

        ppmsNewUserServiceMock.assertNotInvoked().validatePassword(Data.USERNAME, Data.PASSWORD);
        ppmsNewUserServiceMock.assertInvoked().findExperimenterFromExternalSource(Data.USERNAME);
        ppmsNewUserServiceMock.assertInvoked().synchronizeUserFromExternalSource(Data.USERNAME);
        ldapProviderMock.assertInvoked().checkPassword(Data.USERNAME, Data.PASSWORD, readOnly);
    }

    @Test
    public void secondaryProviderShouldCheckAuthWhenUserPrimaryFails() {
        ldapProviderMock.returns(false).checkPassword(Data.USERNAME, Data.PASSWORD, readOnly);
        ppmsNewUserServiceMock.returns(true).isEnabled();
        ppmsNewUserServiceMock.returns(dummyUser).findExperimenterFromExternalSource(Data.USERNAME);

        Boolean result = synchronizingProviders.checkPassword(Data.USERNAME, Data.PASSWORD, readOnly);
        assertNotNull(result, "Non-null result expected");
        assertFalse(result, "Incorrect result");

        ppmsNewUserServiceMock.assertNotInvoked().validatePassword(Data.USERNAME, Data.PASSWORD);
        ppmsNewUserServiceMock.assertInvoked().findExperimenterFromExternalSource(Data.USERNAME);
        ppmsNewUserServiceMock.assertNotInvoked().synchronizeUserFromExternalSource(Data.USERNAME);
        ldapProviderMock.assertInvoked().checkPassword(Data.USERNAME, Data.PASSWORD, readOnly);
    }

    @Test
    public void secondaryProviderShouldNotCheckAuthWhenUserPrimaryDefaultsAndUserIsUnknown() {
        ldapProviderMock.returns(null).checkPassword(Data.USERNAME, Data.PASSWORD, readOnly);
        ppmsNewUserServiceMock.returns(true).isEnabled();

        Boolean result = synchronizingProviders.checkPassword(Data.USERNAME, Data.PASSWORD, readOnly);
        assertNull(result, "Null result expected");

        ppmsNewUserServiceMock.assertInvoked().findExperimenterFromExternalSource(Data.USERNAME);
        ppmsNewUserServiceMock.assertNotInvoked().validatePassword(Data.USERNAME, Data.PASSWORD);
        ppmsNewUserServiceMock.assertNotInvoked().synchronizeUserFromExternalSource(Data.USERNAME);
        ldapProviderMock.assertNotInvoked().checkPassword(Data.USERNAME, Data.PASSWORD, readOnly);
    }

    @Test
    public void secondaryProviderShouldCheckAuthWhenUserPrimaryDefaultsAndUserIsKnownWithAuth() {
        ldapProviderMock.returns(null).checkPassword(Data.USERNAME, Data.PASSWORD, readOnly);
        ppmsNewUserServiceMock.returns(true).isEnabled();
        ppmsNewUserServiceMock.returns(new Experimenter()).findExperimenterFromExternalSource(Data.USERNAME);
        ppmsNewUserServiceMock.returns(true).validatePassword(Data.USERNAME, Data.PASSWORD);

        Boolean result = synchronizingProviders.checkPassword(Data.USERNAME, Data.PASSWORD, readOnly);
        assertNotNull(result, "Non-null result expected");
        assertTrue(result, "Incorrect result");

        ppmsNewUserServiceMock.assertInvoked().findExperimenterFromExternalSource(Data.USERNAME);
        ppmsNewUserServiceMock.assertInvoked().validatePassword(Data.USERNAME, Data.PASSWORD);
        ppmsNewUserServiceMock.assertInvoked().synchronizeUserFromExternalSource(Data.USERNAME);
        ldapProviderMock.assertInvoked().checkPassword(Data.USERNAME, Data.PASSWORD, readOnly);
    }

    @Test
    public void secondaryProviderShouldCheckAuthWhenUserPrimaryDefaultsAndUserIsKnownWithoutAuth() {
        ldapProviderMock.returns(null).checkPassword(Data.USERNAME, Data.PASSWORD, readOnly);
        ppmsNewUserServiceMock.returns(true).isEnabled();
        ppmsNewUserServiceMock.returns(new Experimenter()).findExperimenterFromExternalSource(Data.USERNAME);
        ppmsNewUserServiceMock.returns(false).validatePassword(Data.USERNAME, Data.PASSWORD);

        Boolean result = synchronizingProviders.checkPassword(Data.USERNAME, Data.PASSWORD, readOnly);
        assertNotNull(result, "Non-null result expected");
        assertFalse(result, "Incorrect result");

        ppmsNewUserServiceMock.assertInvoked().findExperimenterFromExternalSource(Data.USERNAME);
        ppmsNewUserServiceMock.assertInvoked().validatePassword(Data.USERNAME, Data.PASSWORD);
        ppmsNewUserServiceMock.assertNotInvoked().synchronizeUserFromExternalSource(Data.USERNAME);
        ldapProviderMock.assertInvoked().checkPassword(Data.USERNAME, Data.PASSWORD, readOnly);
    }

}
