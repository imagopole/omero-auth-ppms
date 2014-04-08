package org.imagopole.omero.auth.impl.ppms;

import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertNull;

import org.imagopole.omero.auth.TestsUtil.Data;
import org.imagopole.omero.auth.api.ppms.PpmsUserDetails;
import org.imagopole.ppms.api.PumapiClient;
import org.imagopole.ppms.api.dto.PpmsGroup;
import org.imagopole.ppms.api.dto.PpmsUser;
import org.testng.annotations.Test;
import org.unitils.UnitilsTestNG;
import org.unitils.inject.annotation.InjectIntoByType;
import org.unitils.inject.annotation.TestedObject;
import org.unitils.mock.Mock;
import org.unitils.mock.annotation.Dummy;
import org.unitils.mock.core.MockObject;

public class DefaultPpmsServiceTest extends UnitilsTestNG {

    /** PPMS service layer */
    @TestedObject
    private DefaultPpmsService ppmsService;

    /** PUMAPI HTTP client */
    @InjectIntoByType
    private Mock<PumapiClient> pumapiClientMock;

    @Dummy
    private PpmsGroup dummyPpmsGroup;

    @Test
    public void findUserByNameTest() {
        // define behaviour
        pumapiClientMock.returns(null).getUser("user-not-found");

        // run test
        PpmsUser result = ppmsService.findUserByName("user-not-found");

        // assert results + invocations
        assertNull(result, "Null results expected");
        pumapiClientMock.assertInvoked().getUser("user-not-found");
    }

    @Test
    public void findUserAndGroupByNameTest() {
        // define behaviour
        Mock<PpmsUser> ppmsUserMock = new MockObject<PpmsUser>(PpmsUser.class, null);
        ppmsUserMock.returns("some.unit.login").getUnitlogin();

        pumapiClientMock.returns(ppmsUserMock.getMock()).getUser(Data.USERNAME);
        pumapiClientMock.returns(dummyPpmsGroup).getGroup("some.unit.login");

        // run test
        PpmsUserDetails result = ppmsService.findUserAndGroupByName(Data.USERNAME);

        // assert results + invocations
        assertNotNull(result, "Non null result expected");
        assertNotNull(result.getUser(), "Non null user expected");
        assertNotNull(result.getGroup(), "Non null group expected");
        pumapiClientMock.assertInvoked().getUser(Data.USERNAME);
        pumapiClientMock.assertInvoked().getGroup("some.unit.login");
    }

}
