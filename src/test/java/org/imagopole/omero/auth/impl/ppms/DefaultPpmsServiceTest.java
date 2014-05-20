package org.imagopole.omero.auth.impl.ppms;

import static org.imagopole.omero.auth.TestsUtil.autonomousRights;
import static org.imagopole.omero.auth.TestsUtil.inactiveRights;
import static org.imagopole.omero.auth.TestsUtil.inactiveSystem;
import static org.imagopole.omero.auth.TestsUtil.inactiveUnit;
import static org.imagopole.omero.auth.TestsUtil.newFooUser;
import static org.imagopole.omero.auth.TestsUtil.newOpenSystem;
import static org.imagopole.omero.auth.TestsUtil.newRestrictedSystem;
import static org.imagopole.omero.auth.TestsUtil.noviceRights;
import static org.imagopole.omero.auth.TestsUtil.superUserRights;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertNull;

import java.util.Collections;
import java.util.List;

import org.imagopole.omero.auth.TestsUtil.Data;
import org.imagopole.omero.auth.TestsUtil.PpmsUnit;
import org.imagopole.omero.auth.api.ExternalServiceException;
import org.imagopole.omero.auth.api.ppms.PpmsUserDetails;
import org.imagopole.ppms.api.PumapiClient;
import org.imagopole.ppms.api.PumapiException;
import org.imagopole.ppms.api.dto.PpmsGroup;
import org.imagopole.ppms.api.dto.PpmsSystem;
import org.imagopole.ppms.api.dto.PpmsUser;
import org.imagopole.ppms.api.dto.PpmsUserPrivilege;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.unitils.UnitilsTestNG;
import org.unitils.inject.annotation.InjectIntoByType;
import org.unitils.inject.annotation.TestedObject;
import org.unitils.mock.Mock;

public class DefaultPpmsServiceTest extends UnitilsTestNG {

    /** Fixture exception message. */
    private static final String PUMAPI_EXCEPTION_MSG = "should.be.translated";

    /** PPMS service layer */
    @TestedObject
    private DefaultPpmsService ppmsService;

    /** PUMAPI HTTP client */
    @InjectIntoByType
    private Mock<PumapiClient> pumapiClientMock;

    /**
     * Data format:
     * { fixtureUserRights, fixtureSystem, fixtureSystemId,
     *   findActiveSystemsExpectedCount, findActiveSystemsWithAutonomyExpectedCount,
     *   findActiveSystemsExpectedRpc, findActiveSystemsWithAutonomyExpectedRpc }
     **/
    @DataProvider(name="systemsAndPrivilegesDataProvider")
    private Object[][] provideUserPrivileges() {
        return new Object[][] {
            { null,                                      null,            0L, 0, 0, false, false },
            { null,                                      newOpenSystem(), 0L, 0, 0, false, false },
            { Collections.emptyList(),                   newOpenSystem(), 0L, 0, 0, false, false },

            // active, "open" system
            { inactiveRights(PpmsUnit.OPEN_SYSTEM_ID),   newOpenSystem(), PpmsUnit.OPEN_SYSTEM_ID, 0, 0, false, false },
            { noviceRights(PpmsUnit.OPEN_SYSTEM_ID),     newOpenSystem(), PpmsUnit.OPEN_SYSTEM_ID, 1, 1, true, true },
            { autonomousRights(PpmsUnit.OPEN_SYSTEM_ID), newOpenSystem(), PpmsUnit.OPEN_SYSTEM_ID, 1, 1, true, true },
            { superUserRights(PpmsUnit.OPEN_SYSTEM_ID) , newOpenSystem(), PpmsUnit.OPEN_SYSTEM_ID, 1, 1, true, true },

            // active, "restricted" system
            { inactiveRights(PpmsUnit.RESTRICTED_SYSTEM_ID),   newRestrictedSystem(), PpmsUnit.RESTRICTED_SYSTEM_ID, 0, 0, false, false },
            { noviceRights(PpmsUnit.RESTRICTED_SYSTEM_ID),     newRestrictedSystem(), PpmsUnit.RESTRICTED_SYSTEM_ID, 1, 0, true, true },
            { autonomousRights(PpmsUnit.RESTRICTED_SYSTEM_ID), newRestrictedSystem(), PpmsUnit.RESTRICTED_SYSTEM_ID, 1, 1, true, true },
            { superUserRights(PpmsUnit.RESTRICTED_SYSTEM_ID) , newRestrictedSystem(), PpmsUnit.RESTRICTED_SYSTEM_ID, 1, 1, true, true },

            // inactive, "open" system
            { inactiveRights(PpmsUnit.INACTIVE_SYSTEM_ID),   inactiveSystem(), PpmsUnit.INACTIVE_SYSTEM_ID, 0, 0, false, false },
            { noviceRights(PpmsUnit.INACTIVE_SYSTEM_ID),     inactiveSystem(), PpmsUnit.INACTIVE_SYSTEM_ID, 0, 0, true, true },
            { autonomousRights(PpmsUnit.INACTIVE_SYSTEM_ID), inactiveSystem(), PpmsUnit.INACTIVE_SYSTEM_ID, 0, 0, true, true },
            { superUserRights(PpmsUnit.INACTIVE_SYSTEM_ID) , inactiveSystem(), PpmsUnit.INACTIVE_SYSTEM_ID, 0, 0, true, true }
        };
    }

    @DataProvider(name="findUserAndGroupByNameNotFoundDataProvider")
    private Object[][] provideInvalidUnitLogins() {
        return new Object[][] {
            { null },
            { ""   }
        };
    }

    @Test(dataProvider = "systemsAndPrivilegesDataProvider")
    public void findActiveSystemsByUserNameTests(
                    List<PpmsUserPrivilege> fixtureUserRights,
                    PpmsSystem fixtureSystem,
                    Long fixtureSystemId,
                    int findActiveSystemsExpectedCount,
                    int findActiveSystemsWithAutonomyExpectedCount,
                    boolean findActiveSystemsExpectedRpc,
                    boolean findActiveSystemsWithAutonomyExpectedRpc) {
        // define behaviour
        pumapiClientMock.returns(fixtureUserRights).getUserRights(Data.USERNAME);
        pumapiClientMock.returns(fixtureSystem).getSystem(fixtureSystemId);

        // run test
        List<PpmsSystem> result = ppmsService.findActiveSystemsByUserName(Data.USERNAME);

        // assert results + invocations
        assertNotNull(result, "Non null result expected");
        assertEquals(result.size(), findActiveSystemsExpectedCount, "Incorrect results");

        pumapiClientMock.assertInvoked().getUserRights(Data.USERNAME);
        if (findActiveSystemsExpectedRpc) {
            pumapiClientMock.assertInvoked().getSystem(fixtureSystemId);
        } else {
            pumapiClientMock.assertNotInvoked().getSystem(fixtureSystemId);
        }
    }

    @Test(dataProvider = "systemsAndPrivilegesDataProvider")
    public void findActiveSystemsWithAutonomyByUserNameTests(
                    List<PpmsUserPrivilege> fixtureUserRights,
                    PpmsSystem fixtureSystem,
                    Long fixtureSystemId,
                    int findActiveSystemsExpectedCount,
                    int findActiveSystemsWithAutonomyExpectedCount,
                    boolean findActiveSystemsExpectedRpc,
                    boolean findActiveSystemsWithAutonomyExpectedRpc) {
        // define behaviour
        pumapiClientMock.returns(fixtureUserRights).getUserRights(Data.USERNAME);
        pumapiClientMock.returns(fixtureSystem).getSystem(fixtureSystemId);

        // run test
        List<PpmsSystem> result = ppmsService.findActiveSystemsWithAutonomyByUserName(Data.USERNAME);

        // assert results + invocations
        assertNotNull(result, "Non null result expected");
        assertEquals(result.size(), findActiveSystemsWithAutonomyExpectedCount, "Incorrect results");

        pumapiClientMock.assertInvoked().getUserRights(Data.USERNAME);
        if (findActiveSystemsWithAutonomyExpectedRpc) {
            pumapiClientMock.assertInvoked().getSystem(fixtureSystemId);
        } else {
            pumapiClientMock.assertNotInvoked().getSystem(fixtureSystemId);
        }
    }

    @Test
    public void findGroupByUserNameFoundTest() {
        // define behaviour
        PpmsUser ppmsUser = newFooUser();
        ppmsUser.setUnitlogin(PpmsUnit.UNIT_LOGIN);

        pumapiClientMock.returns(ppmsUser).getUser(PpmsUnit.OMERO_USER);
        pumapiClientMock.returns(inactiveUnit(PpmsUnit.UNIT_LOGIN)).getGroup(PpmsUnit.UNIT_LOGIN);

        // run test
        PpmsGroup result = ppmsService.findGroupByUserName(PpmsUnit.OMERO_USER);

        // assert results + invocations
        assertNotNull(result, "Non null result expected");
        pumapiClientMock.assertInvoked().getUser(PpmsUnit.OMERO_USER);
        pumapiClientMock.assertInvoked().getGroup(PpmsUnit.UNIT_LOGIN);
    }

    @Test
    public void findGroupByUserNameNotFoundTest() {
        // define behaviour
        pumapiClientMock.returns(null).getUser(PpmsUnit.OMERO_USER);
        pumapiClientMock.returns(null).getGroup(PpmsUnit.UNIT_LOGIN);

        // run test
        PpmsGroup result = ppmsService.findGroupByUserName(PpmsUnit.OMERO_USER);

        // assert results + invocations
        assertNull(result, "Null results expected");
        pumapiClientMock.assertInvoked().getUser(PpmsUnit.OMERO_USER);
        pumapiClientMock.assertNotInvoked().getGroup(PpmsUnit.UNIT_LOGIN);
    }

    @Test(expectedExceptions = UnsupportedOperationException.class)
    public void findProjectsByUserNameTests() {
        ppmsService.findProjectsByUserName(Data.USERNAME);
    }

    @Test
    public void findUserAndGroupByNameFoundTest() {
        // define behaviour
        PpmsUser ppmsUser = newFooUser();
        ppmsUser.setUnitlogin(PpmsUnit.UNIT_LOGIN);

        pumapiClientMock.returns(ppmsUser).getUser(PpmsUnit.OMERO_USER);
        pumapiClientMock.returns(inactiveUnit(PpmsUnit.UNIT_LOGIN)).getGroup(PpmsUnit.UNIT_LOGIN);

        // run test
        PpmsUserDetails result = ppmsService.findUserAndGroupByName(PpmsUnit.OMERO_USER);

        // assert results + invocations
        assertNotNull(result, "Non null result expected");
        assertNotNull(result.getUser(), "Non null user expected");
        assertNotNull(result.getGroup(), "Non null group expected");
        pumapiClientMock.assertInvoked().getUser(PpmsUnit.OMERO_USER);
        pumapiClientMock.assertInvoked().getGroup(PpmsUnit.UNIT_LOGIN);
    }

    @Test(dataProvider = "findUserAndGroupByNameNotFoundDataProvider")
    public void findUserAndGroupByNameNotFoundTests(String fixtureUnitLogin) {
        // define behaviour
        PpmsUser ppmsUser = newFooUser();
        ppmsUser.setUnitlogin(fixtureUnitLogin);

        // assume a wonky user with some dodgy group identifier (should-not-happen-tm)
        pumapiClientMock.returns(ppmsUser).getUser(PpmsUnit.OMERO_USER);
        pumapiClientMock.returns(null).getGroup(fixtureUnitLogin);

        // run test
        PpmsUserDetails result = ppmsService.findUserAndGroupByName(PpmsUnit.OMERO_USER);

        // assert results + invocations
        assertNull(result, "Null result expected");
        pumapiClientMock.assertInvoked().getUser(PpmsUnit.OMERO_USER);
        pumapiClientMock.assertNotInvoked().getGroup(fixtureUnitLogin);
    }

    @Test
    public void findUserByNameNotFoundTest() {
        // define behaviour
        pumapiClientMock.returns(null).getUser("user-not-found");

        // run test
        PpmsUser result = ppmsService.findUserByName("user-not-found");

        // assert results + invocations
        assertNull(result, "Null results expected");
        pumapiClientMock.assertInvoked().getUser("user-not-found");
    }

    @Test
    public void findUserByNameFoundTest() {
        // define behaviour
        pumapiClientMock.returns(newFooUser()).getUser(PpmsUnit.OMERO_USER);

        // run test
        PpmsUser result = ppmsService.findUserByName(PpmsUnit.OMERO_USER);

        // assert results + invocations
        assertNotNull(result, "Non null result expected");
        assertNull(result.getActive(),"Null field expected");
        assertEquals(result.getFname(), PpmsUnit.OMERO_USER_GN, "Incorrect results");
        assertEquals(result.getLname(), PpmsUnit.OMERO_USER_SN, "Incorrect results");
        assertEquals(result.getEmail(), PpmsUnit.OMERO_USER_EMAIL, "Incorrect results");
        pumapiClientMock.assertInvoked().getUser(PpmsUnit.OMERO_USER);
    }

    @Test(expectedExceptions = { ExternalServiceException.class },
          expectedExceptionsMessageRegExp = PUMAPI_EXCEPTION_MSG)
    public void checkAuthenticationShouldWrapExceptions() {
        pumapiClientMock.raises(new PumapiException(PUMAPI_EXCEPTION_MSG)).authenticate(Data.USERNAME, Data.PASSWORD);

        ppmsService.checkAuthentication(Data.USERNAME, Data.PASSWORD);
    }

    @Test(expectedExceptions = { ExternalServiceException.class },
          expectedExceptionsMessageRegExp = PUMAPI_EXCEPTION_MSG)
    public void findActiveSystemsByUserNameShouldWrapExceptions() {
        pumapiClientMock.raises(new PumapiException(PUMAPI_EXCEPTION_MSG)).getUserRights(Data.USERNAME);

        ppmsService.findActiveSystemsByUserName(Data.USERNAME);
    }

    @Test(expectedExceptions = { ExternalServiceException.class },
          expectedExceptionsMessageRegExp = PUMAPI_EXCEPTION_MSG)
    public void findActiveSystemsWithAutonomyByUserNameShouldWrapExceptions() {
        pumapiClientMock.raises(new PumapiException(PUMAPI_EXCEPTION_MSG)).getUserRights(Data.USERNAME);

        ppmsService.findActiveSystemsWithAutonomyByUserName(Data.USERNAME);
    }

    @Test(expectedExceptions = { ExternalServiceException.class },
          expectedExceptionsMessageRegExp = PUMAPI_EXCEPTION_MSG)
    public void findGroupByUserNameShouldWrapExceptions() {
        pumapiClientMock.raises(new PumapiException(PUMAPI_EXCEPTION_MSG)).getUser(Data.USERNAME);

        ppmsService.findGroupByUserName(Data.USERNAME);
    }

    @Test(expectedExceptions = { UnsupportedOperationException.class })
    public void findProjectsByUserNameShouldWrapExceptions() {
        pumapiClientMock.raises(new PumapiException(PUMAPI_EXCEPTION_MSG)).getUser(Data.USERNAME);

        ppmsService.findProjectsByUserName(Data.USERNAME);
    }

    @Test(expectedExceptions = { ExternalServiceException.class },
          expectedExceptionsMessageRegExp = PUMAPI_EXCEPTION_MSG)
    public void findUserAndGroupByNameShouldWrapExceptions() {
        pumapiClientMock.raises(new PumapiException(PUMAPI_EXCEPTION_MSG)).getUser(Data.USERNAME);

        ppmsService.findUserAndGroupByName(Data.USERNAME);
    }

    @Test(expectedExceptions = { ExternalServiceException.class },
          expectedExceptionsMessageRegExp = PUMAPI_EXCEPTION_MSG)
    public void findUserByNameShouldWrapExceptions() {
        pumapiClientMock.raises(new PumapiException(PUMAPI_EXCEPTION_MSG)).getUser(Data.USERNAME);

        ppmsService.findUserByName(Data.USERNAME);
    }

}
