package org.imagopole.omero.auth.impl.group;

import java.util.Arrays;
import java.util.List;

import ome.model.internal.Permissions;
import ome.security.auth.RoleProvider;

import org.imagopole.omero.auth.TestsUtil;
import org.imagopole.omero.auth.api.ExternalAuthConfig;
import org.imagopole.omero.auth.api.dto.NamedItem;
import org.imagopole.omero.auth.impl.DefaultExternalAuthConfig.ConfigValues;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.unitils.UnitilsTestNG;
import org.unitils.inject.annotation.InjectIntoByType;
import org.unitils.inject.annotation.TestedObject;
import org.unitils.mock.Mock;
import org.unitils.mock.PartialMock;

import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertTrue;

public class ConfigurableNameToGroupBeanTest extends UnitilsTestNG {

    /** Application logs */
    //private final Logger log = LoggerFactory.getLogger(ConfigurableNameToGroupBeanTest.class);

    /** NewUserGroupBean under test */
    @TestedObject
    private PartialMock<ConfigurableNameToGroupBean> newUserGroupBeanMock;

    /** External auth config mock collaborator */
    @InjectIntoByType
    private Mock<ExternalAuthConfig> authConfigMock;

    /** OMERO role provider mock collaborator */
    private Mock<RoleProvider> roleProviderMock;

    // fixture data
    private final static String USERNAME = "some.username";
    private final static boolean GROUPS_STRICT_MODE = true;
    private final static String PERMISSIONS_LEVEL = ConfigValues.PRIVATE;
    private final static Permissions PERMISSIONS_FOR_LEVEL = Permissions.USER_PRIVATE;

    @BeforeMethod
    public void setupBeforeMethod() {
        authConfigMock.returns(GROUPS_STRICT_MODE).failOnDuplicateGroups();
        authConfigMock.returns(TestsUtil.OMERO_SYSTEM_GROUPS).listExcludedGroups();
    }

 /*
    newUserGroupBeanMock.assertInvoked().groups(USERNAME, authConfigMock.getMock(), roleProviderMock.getMock());
    newUserGroupBeanMock.assertNotInvoked().getExternalConfig();
    roleProviderMock.assertNotInvoked().createGroup(null, PERMISSIONS_FOR_LEVEL, GROUPS_STRICT_MODE);
    authConfigMock.assertNotInvoked().failOnDuplicateGroups();
    authConfigMock.assertNotInvoked().listExcludedGroups();
*/
    @Test
    public void shouldIgnoreNullGroupNamesList() {
       // define behaviour
       newUserGroupBeanMock.returns(PERMISSIONS_LEVEL).getPermissionLevel();
       newUserGroupBeanMock.returns(null).listItemsByUserName(USERNAME, authConfigMock.getMock());

       // run test
       List<Long> result =
          newUserGroupBeanMock.getMock().groups(USERNAME, authConfigMock.getMock(), roleProviderMock.getMock());

       // assert results + invocations
       assertNotNull(result, "Non null results expected");
       assertTrue(result.isEmpty(), "Empty results expected");
       newUserGroupBeanMock.assertInvoked().groups(USERNAME, authConfigMock.getMock(), roleProviderMock.getMock());
       newUserGroupBeanMock.assertInvoked().listItemsByUserName(USERNAME, authConfigMock.getMock());
       newUserGroupBeanMock.assertNotInvoked().getExternalConfig();
       roleProviderMock.assertNotInvoked().createGroup(null, PERMISSIONS_FOR_LEVEL, GROUPS_STRICT_MODE);
       authConfigMock.assertNotInvoked().failOnDuplicateGroups();
       authConfigMock.assertNotInvoked().listExcludedGroups();
    }

    @Test(dataProvider = "protected-group-names-data-provider")
    public void shouldIgnoreOmeroSystemGroupsNames(String groupName) {
       // define behaviour
       List<NamedItem> items = Arrays.asList(new NamedItem[] { NamedItem.newItem(groupName) } );
       newUserGroupBeanMock.returns(PERMISSIONS_LEVEL).getPermissionLevel();
       newUserGroupBeanMock.returns(items).listItemsByUserName(USERNAME, null);

       // run test
       List<Long> result =
          newUserGroupBeanMock.getMock().groups(USERNAME, authConfigMock.getMock(), roleProviderMock.getMock());

       // assert results + invocations
       assertNotNull(result, "Non null results expected");
       assertTrue(result.isEmpty(), "Empty results expected");
       newUserGroupBeanMock.assertInvoked().groups(USERNAME, authConfigMock.getMock(), roleProviderMock.getMock());
       newUserGroupBeanMock.assertInvoked().listItemsByUserName(USERNAME, authConfigMock.getMock());
       roleProviderMock.assertNotInvoked().createGroup(groupName, PERMISSIONS_FOR_LEVEL, GROUPS_STRICT_MODE);
       authConfigMock.assertInvoked().failOnDuplicateGroups();
       authConfigMock.assertInvoked().listExcludedGroups();
    }

    @Test
    public void groupsTest() {
       // define behaviour
       String groupName = "some.group.name";
       List<NamedItem> items = Arrays.asList(new NamedItem[] { NamedItem.newItem(groupName) } );
       newUserGroupBeanMock.returns(PERMISSIONS_LEVEL).getPermissionLevel();
       newUserGroupBeanMock.returns(items).listItemsByUserName(USERNAME, null);

       // run test
       List<Long> result =
          newUserGroupBeanMock.getMock().groups(USERNAME, authConfigMock.getMock(), roleProviderMock.getMock());

       // assert results + invocations
       assertNotNull(result, "Non null results expected");
       assertTrue(result.size() == 1, "One result expected");
       newUserGroupBeanMock.assertInvoked().groups(USERNAME, authConfigMock.getMock(), roleProviderMock.getMock());
       newUserGroupBeanMock.assertInvoked().listItemsByUserName(USERNAME, authConfigMock.getMock());
       roleProviderMock.assertInvoked().createGroup(groupName, PERMISSIONS_FOR_LEVEL, GROUPS_STRICT_MODE);
       authConfigMock.assertInvoked().failOnDuplicateGroups();
       authConfigMock.assertInvoked().listExcludedGroups();
    }

    @DataProvider(name="protected-group-names-data-provider")
    private Object[][] provideOmeroInternalGroupNames() {
        return new Object[][] {
            { "system" },
            { "user" },
            { "guest" },
            { "default" },
        };
    }

}
