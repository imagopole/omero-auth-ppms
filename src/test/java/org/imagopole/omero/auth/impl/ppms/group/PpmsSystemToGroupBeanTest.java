package org.imagopole.omero.auth.impl.ppms.group;

import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertTrue;

import java.util.List;

import ome.security.auth.RoleProvider;

import org.imagopole.omero.auth.TestsUtil;
import org.imagopole.omero.auth.TestsUtil.Data;
import org.imagopole.omero.auth.api.ExternalAuthConfig;
import org.imagopole.omero.auth.api.ppms.PpmsService;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.unitils.UnitilsTestNG;
import org.unitils.inject.annotation.InjectIntoByType;
import org.unitils.inject.annotation.TestedObject;
import org.unitils.mock.Mock;

public class PpmsSystemToGroupBeanTest extends UnitilsTestNG {

    /** NewUserGroupBean under test */
    @TestedObject
    private PpmsSystemToGroupBean newUserGroupBean;

    /** PPMS service mock collaborator */
    @InjectIntoByType
    private Mock<PpmsService> ppmsServiceMock;

    /** External auth config mock collaborator */
    @InjectIntoByType
    private Mock<ExternalAuthConfig> authConfigMock;

    /** OMERO role provider mock collaborator */
    private Mock<RoleProvider> roleProviderMock;

    @BeforeMethod
    public void setupBeforeMethod() {
        authConfigMock.returns(Data.GROUPS_STRICT_MODE).failOnDuplicateGroups();
        authConfigMock.returns(TestsUtil.OMERO_SYSTEM_GROUPS).listExcludedGroups();
    }

    @Test
    public void shouldReturnEmptyGroupsListForNullSystemsList() {
       // define behaviour
       ppmsServiceMock.returns(null).findSystemsByUserName(Data.USERNAME);

       // run test
       List<Long> result =
          newUserGroupBean.groups(Data.USERNAME, authConfigMock.getMock(), roleProviderMock.getMock());

       // assert results + invocations
       assertNotNull(result, "Non null results expected");
       assertTrue(result.isEmpty(), "Empty results expected");
       ppmsServiceMock.assertInvoked().findSystemsByUserName(Data.USERNAME);
       roleProviderMock.assertNotInvoked().createGroup(
                       null,
                       Data.PERMISSIONS_FOR_LEVEL,
                       Data.GROUPS_STRICT_MODE);
       authConfigMock.assertNotInvoked().failOnDuplicateGroups();
       authConfigMock.assertNotInvoked().listExcludedGroups();
    }

}
