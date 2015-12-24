package org.imagopole.omero.auth.impl.group;

import static org.testng.Assert.assertNotNull;
import static org.unitils.reflectionassert.ReflectionAssert.assertReflectionEquals;

import java.util.Arrays;
import java.util.List;

import ome.security.auth.NewUserGroupBean;

import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.unitils.UnitilsTestNG;
import org.unitils.mock.Mock;

public class NewUserGroupBeansTest extends UnitilsTestNG {

    /** @TestedObject */
    private NewUserGroupBeans newUserGroupBeans;

    /** NewUserGroupBean mock collaborators */
    private Mock<NewUserGroupBean> firstChainedGroupBeanMock;
    private Mock<NewUserGroupBean> secondChainedGroupBeanMock;

    @BeforeMethod
    public void setupBeforeMethod() {
         newUserGroupBeans = new NewUserGroupBeans(Arrays.asList(
                                                        firstChainedGroupBeanMock.getMock(),
                                                        secondChainedGroupBeanMock.getMock()));
    }

    @Test
    public void groupsShouldHonorChainOrdering() {
        // define behaviour
        firstChainedGroupBeanMock.returns(Arrays.asList(20L, 10L)).groups("username", null, null, null, null);
        secondChainedGroupBeanMock.returns(Arrays.asList(1L)).groups("username", null, null, null, null);

        // run test
        List<Long> result = newUserGroupBeans.groups("username", null, null, null, null);

        // assert results + invocations
        assertNotNull(result, "Non null results expected");
        assertReflectionEquals(Arrays.asList(20L, 10L, 1L), result);
        firstChainedGroupBeanMock.assertInvoked().groups("username", null, null, null, null);
        secondChainedGroupBeanMock.assertInvoked().groups("username", null, null, null, null);
    }

}
