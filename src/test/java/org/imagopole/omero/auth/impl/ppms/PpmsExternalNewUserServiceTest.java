package org.imagopole.omero.auth.impl.ppms;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertNull;

import java.util.Properties;

import ome.model.meta.Experimenter;
import ome.system.OmeroContext;

import org.imagopole.omero.auth.AbstractOmeroServerTest;
import org.imagopole.omero.auth.TestsUtil;
import org.imagopole.omero.auth.TestsUtil.Data;
import org.imagopole.omero.auth.TestsUtil.Groups;
import org.imagopole.omero.auth.TestsUtil.PpmsUnit;
import org.imagopole.omero.auth.api.ppms.PpmsService;
import org.imagopole.omero.auth.impl.ppms.user.PpmsExternalNewUserService;
import org.imagopole.ppms.api.dto.PpmsUser;
import org.testng.annotations.Test;
import org.unitils.mock.Mock;

public class PpmsExternalNewUserServiceTest extends AbstractOmeroServerTest {

    /** @TestedObject */
    private PpmsExternalNewUserService ppmsNewUserService;

    /** PUMAPI HTTP client */
    private Mock<PpmsService> ppmsServiceMock;


    @Override
    protected void setUpBeforeServerStartup(Properties systemProps) {
    }

    @Override
    protected void setUpAfterServerStartup(OmeroContext omeroContext) {
        ppmsNewUserService = (PpmsExternalNewUserService) omeroContext.getBean("ppmsNewUserService");
    }

    @Test(groups = { Groups.INTEGRATION })
    public void findExperimenterFromExternalSourceShouldIgnoreUnknownUsers() {
        // define behaviour
        ppmsServiceMock.returns(null).findUserByName(Data.USERNAME);
        ppmsNewUserService.setPpmsService(ppmsServiceMock.getMock());

        // test
        Experimenter result = ppmsNewUserService.findExperimenterFromExternalSource(Data.USERNAME);

        // assertions
        assertNull(result, "Null result expected");
        ppmsServiceMock.assertInvoked().findUserByName(Data.USERNAME);
    }

    @Test(groups = { Groups.INTEGRATION })
    public void findExperimenterFromExternalSourceShouldConvertActiveUsers() {
        // define behaviour
        PpmsUser ppmsUnitUser = TestsUtil.newPpmsUser();
        ppmsUnitUser.setActive(true);

        ppmsServiceMock.returns(ppmsUnitUser).findUserByName(PpmsUnit.DEFAULT_USER);
        ppmsNewUserService.setPpmsService(ppmsServiceMock.getMock());

        // test
        Experimenter result = ppmsNewUserService.findExperimenterFromExternalSource(PpmsUnit.DEFAULT_USER);

        // assertions
        assertNotNull(result, "Non null results expected");
        assertEquals(result.getFirstName(), PpmsUnit.DEFAULT_USER_GN, "Incorrect results");
        assertEquals(result.getLastName(), PpmsUnit.DEFAULT_USER_SN, "Incorrect results");
        assertEquals(result.getEmail(), PpmsUnit.DEFAULT_USER_EMAIL, "Incorrect results");
        assertNull(result.getInstitution(), "Null expected");
        ppmsServiceMock.assertInvoked().findUserByName(PpmsUnit.DEFAULT_USER);
    }

    @Test(groups = { Groups.INTEGRATION })
    public void findExperimenterFromExternalSourceShouldIgnoreInactiveUsers() {
        // define behaviour
        PpmsUser ppmsUnitUser = TestsUtil.newPpmsUser();
        ppmsUnitUser.setActive(false);

        ppmsServiceMock.returns(ppmsUnitUser).findUserByName(PpmsUnit.DEFAULT_USER);
        ppmsNewUserService.setPpmsService(ppmsServiceMock.getMock());

        // test
        Experimenter result = ppmsNewUserService.findExperimenterFromExternalSource(PpmsUnit.DEFAULT_USER);

        // assertions
        assertNull(result, "Null result expected");
        ppmsServiceMock.assertInvoked().findUserByName(PpmsUnit.DEFAULT_USER);
    }

    @Test(groups = { Groups.INTEGRATION })
    public void findExperimenterFromExternalSourceShouldIgnoreUsersWithUnknownActivityStatus() {
        // define behaviour
        PpmsUser ppmsUnitUser = TestsUtil.newPpmsUser();
        ppmsUnitUser.setActive(null);

        ppmsServiceMock.returns(ppmsUnitUser).findUserByName(PpmsUnit.DEFAULT_USER);
        ppmsNewUserService.setPpmsService(ppmsServiceMock.getMock());

        // test
        Experimenter result = ppmsNewUserService.findExperimenterFromExternalSource(PpmsUnit.DEFAULT_USER);

        // assertions
        assertNull(result, "Null result expected");
        ppmsServiceMock.assertInvoked().findUserByName(PpmsUnit.DEFAULT_USER);
    }

}
