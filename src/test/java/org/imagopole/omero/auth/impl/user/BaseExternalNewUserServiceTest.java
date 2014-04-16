package org.imagopole.omero.auth.impl.user;

import ome.conditions.ApiUsageException;

import org.imagopole.omero.auth.TestsUtil.Data;
import org.imagopole.omero.auth.api.ExternalAuthConfig;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.testng.annotations.Test;
import org.unitils.UnitilsTestNG;
import org.unitils.inject.annotation.InjectIntoByType;
import org.unitils.inject.annotation.TestedObject;
import org.unitils.mock.Mock;
import org.unitils.mock.PartialMock;

public class BaseExternalNewUserServiceTest extends UnitilsTestNG {

    @TestedObject
    private PartialMock<BaseExternalNewUserService> externalNewUserServiceMock;

    @InjectIntoByType
    private Mock<ExternalAuthConfig> authConfigMock;

    // blegh... NPE prevention in partial mock
    @InjectIntoByType
    private Logger log = LoggerFactory.getLogger(BaseExternalNewUserService.class);

    @Test(expectedExceptions = { ApiUsageException.class },
          expectedExceptionsMessageRegExp = "^Cannot find user in external source.*")
    public void createUserFromExternalSourceShouldFailOnUserNotFound() {
        // behaviour
        externalNewUserServiceMock.returns(null).findExperimenterFromExternalSource(Data.USERNAME);

        // test
        externalNewUserServiceMock.getMock().createUserFromExternalSource(Data.USERNAME, Data.PASSWORD);
    }

}
