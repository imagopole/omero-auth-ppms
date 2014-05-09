package org.imagopole.omero.auth.impl;

import static org.imagopole.omero.auth.TestsUtil.activate;
import static org.imagopole.omero.auth.TestsUtil.newFooUser;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertNull;

import java.util.Properties;

import ome.system.OmeroContext;

import org.imagopole.omero.auth.AbstractOmeroServerTest;
import org.imagopole.omero.auth.TestsUtil.Groups;
import org.imagopole.omero.auth.TestsUtil.PpmsUnit;
import org.imagopole.omero.auth.impl.ppms.DefaultPpmsService;
import org.imagopole.ppms.api.PumapiClient;
import org.imagopole.ppms.api.PumapiException;
import org.testng.annotations.Test;
import org.unitils.mock.Mock;
import org.unitils.mock.core.MockObject;

public class ExternalPasswordProviderFaultTest extends AbstractOmeroServerTest {

    /** @TestedObject */
    private ExternalConfigurablePasswordProvider passwordProvider;

    private Mock<PumapiClient> pumapiClientMock;

    DefaultPpmsService ppmsService;

    @Override
    protected void setUpBeforeServerStartup(Properties systemProps) {
    }

    @Override
    protected void setUpAfterServerStartup(OmeroContext omeroContext) {
        this.passwordProvider = (ExternalConfigurablePasswordProvider) omeroContext.getBean("ppmsPasswordProvider");

        // override the "remote" PPMS client from the spring context with a mock implementation
        pumapiClientMock = new MockObject<PumapiClient>(PumapiClient.class, null);
        ppmsService = (DefaultPpmsService) omeroContext.getBean("ppmsService");
        ppmsService.setPpmsClient(pumapiClientMock.getMock());
    }

    @Test(groups = { Groups.INTEGRATION })
    public void hasUsernameShouldReturnNullWhenServiceIsFaulty() {
        pumapiClientMock.raises(new PumapiException("ppms.failure@hasUser")).getUser(PpmsUnit.OMERO_USER);

        Boolean result = passwordProvider.hasUsername(PpmsUnit.OMERO_USER);

        assertNull(result, "Null result expected");
        pumapiClientMock.assertInvoked().getUser(PpmsUnit.OMERO_USER);
    }

    @Test(groups = { Groups.INTEGRATION })
    public void checkPasswordShouldReturnNullWhenServiceIsFaulty() {
        pumapiClientMock.returns(activate(newFooUser())).getUser(PpmsUnit.OMERO_USER);
        pumapiClientMock.raises(new PumapiException("ppms.failure@checkPwd"))
                            .authenticate(PpmsUnit.OMERO_USER, PpmsUnit.OMERO_PWD);

        Boolean result = passwordProvider.checkPassword(PpmsUnit.OMERO_USER, PpmsUnit.OMERO_PWD, true);

        assertNull(result, "Null result expected");
        pumapiClientMock.assertInvoked().authenticate(PpmsUnit.OMERO_USER, PpmsUnit.OMERO_PWD);
    }

    @Test(groups = { Groups.INTEGRATION })
    public void hasPasswordShouldReturnFalseWhenServiceIsFaulty() {
        pumapiClientMock.raises(new PumapiException("ppms.failure@hasPwd")).getUser(PpmsUnit.OMERO_USER);

        boolean result = passwordProvider.hasPassword(PpmsUnit.OMERO_USER);

        assertFalse(result, "False result expected");
        pumapiClientMock.assertInvoked().getUser(PpmsUnit.OMERO_USER);
    }

}
