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
import org.imagopole.omero.auth.impl.ppms.user.PpmsExternalNewUserService;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.unitils.UnitilsTestNG;
import org.unitils.mock.Mock;
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

    @Test
    public void secondaryProviderShouldCheckAuthWhenUserPrimarySuceeds() {
        ldapProviderMock.returns(true).checkPassword(Data.USERNAME, Data.PASSWORD, true);
        ppmsNewUserServiceMock.returns(true).isEnabled();

        Boolean result = synchronizingProviders.checkPassword(Data.USERNAME, Data.PASSWORD, true);
        assertNotNull(result, "Non-null result expected");
        assertTrue(result, "Incorrect result");

        ppmsNewUserServiceMock.assertNotInvoked().validatePassword(Data.USERNAME, Data.PASSWORD);
    }

    @Test
    public void secondaryProviderShouldCheckAuthWhenUserPrimaryFails() {
        ldapProviderMock.returns(false).checkPassword(Data.USERNAME, Data.PASSWORD, true);
        ppmsNewUserServiceMock.returns(true).isEnabled();

        Boolean result = synchronizingProviders.checkPassword(Data.USERNAME, Data.PASSWORD, true);
        assertNotNull(result, "Non-null result expected");
        assertFalse(result, "Incorrect result");

        ppmsNewUserServiceMock.assertNotInvoked().validatePassword(Data.USERNAME, Data.PASSWORD);
    }

    @Test
    public void secondaryProviderShouldNotCheckAuthWhenUserPrimaryDefaultsAndUserIsUnknown() {
        ldapProviderMock.returns(null).checkPassword(Data.USERNAME, Data.PASSWORD, true);
        ppmsNewUserServiceMock.returns(true).isEnabled();

        Boolean result = synchronizingProviders.checkPassword(Data.USERNAME, Data.PASSWORD, true);
        assertNull(result, "Null result expected");

        ppmsNewUserServiceMock.assertInvoked().findExperimenterFromExternalSource(Data.USERNAME);
        ppmsNewUserServiceMock.assertNotInvoked().validatePassword(Data.USERNAME, Data.PASSWORD);
    }

    @Test
    public void secondaryProviderShouldCheckAuthWhenUserPrimaryDefaultsAndUserIsKnownWithAuth() {
        ldapProviderMock.returns(null).checkPassword(Data.USERNAME, Data.PASSWORD, true);
        ppmsNewUserServiceMock.returns(true).isEnabled();
        ppmsNewUserServiceMock.returns(new Experimenter()).findExperimenterFromExternalSource(Data.USERNAME);
        ppmsNewUserServiceMock.returns(true).validatePassword(Data.USERNAME, Data.PASSWORD);

        Boolean result = synchronizingProviders.checkPassword(Data.USERNAME, Data.PASSWORD, true);
        assertNotNull(result, "Non-null result expected");
        assertTrue(result, "Incorrect result");

        ppmsNewUserServiceMock.assertInvoked().findExperimenterFromExternalSource(Data.USERNAME);
        ppmsNewUserServiceMock.assertInvoked().validatePassword(Data.USERNAME, Data.PASSWORD);
    }

    @Test
    public void secondaryProviderShouldCheckAuthWhenUserPrimaryDefaultsAndUserIsKnownWithoutAuth() {
        ldapProviderMock.returns(null).checkPassword(Data.USERNAME, Data.PASSWORD, true);
        ppmsNewUserServiceMock.returns(true).isEnabled();
        ppmsNewUserServiceMock.returns(new Experimenter()).findExperimenterFromExternalSource(Data.USERNAME);
        ppmsNewUserServiceMock.returns(false).validatePassword(Data.USERNAME, Data.PASSWORD);

        Boolean result = synchronizingProviders.checkPassword(Data.USERNAME, Data.PASSWORD, true);
        assertNotNull(result, "Non-null result expected");
        assertFalse(result, "Incorrect result");

        ppmsNewUserServiceMock.assertInvoked().findExperimenterFromExternalSource(Data.USERNAME);
        ppmsNewUserServiceMock.assertInvoked().validatePassword(Data.USERNAME, Data.PASSWORD);
    }

}
