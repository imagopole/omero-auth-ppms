package org.imagopole.omero.auth.impl.ppms;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;
import net.sf.ehcache.CacheManager;
import net.sf.ehcache.Element;

import org.imagopole.ppms.api.PumapiClient;
import org.imagopole.ppms.api.dto.PpmsGroup;
import org.imagopole.ppms.api.dto.PpmsSystem;
import org.imagopole.ppms.api.dto.PpmsUser;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;
import org.unitils.UnitilsTestNG;
import org.unitils.mock.Mock;
import org.unitils.mock.core.MockObject;

public class CachingPumapiClientTest extends UnitilsTestNG {

    /** @TestedObject */
    private CachingPumapiClient cachingClient;

    /** Actual cache manager instance */
    private CacheManager cacheManager;

    private Mock<PumapiClient> pumapiClientMockDelegate;

    private static final String CACHE_NAME = "pumapiClientCache";

    @BeforeClass
    public void setup() {
        cacheManager = CacheManager.create();
        cacheManager.addCache(CACHE_NAME);
        pumapiClientMockDelegate = new MockObject<PumapiClient>(PumapiClient.class, null);
        this.cachingClient = new CachingPumapiClient(pumapiClientMockDelegate.getMock(), this.cacheManager);
    }

    @AfterMethod
    public void clearCache() {
        cacheManager.clearAll();
    }

    @Test
    public void getUserShouldInvokeDelegateOnColdCache() {
        // define behaviour
        String username = "some.user.not.yet.in.cache";
        PpmsUser dummyUser = new PpmsUser();
        dummyUser.setLogin(username);
        pumapiClientMockDelegate.returns(dummyUser).getUser(username);

        // run test
        PpmsUser result = cachingClient.getUser(username);

        // assert results and invocations
        assertNotNull(result, "Non null results expected");
        assertEquals(result.getLogin(), username, "Incorrect results");

        pumapiClientMockDelegate.assertInvoked().getUser(username);
    }

    @Test
    public void getUserShouldNotInvokeDelegateOnWarmCache() {
        // define behaviour
        String username = "some.user.already.in.cache";
        PpmsUser dummyUser = new PpmsUser();
        dummyUser.setLogin(username);
        pumapiClientMockDelegate.returns(dummyUser).getUser(username);

        // warm-up cache
        cacheManager.getCache(CACHE_NAME).put(new Element("getUser-" + username, dummyUser));

        // run test
        PpmsUser result = cachingClient.getUser(username);

        // assert results and invocations
        assertNotNull(result, "Non null results expected");
        assertEquals(result.getLogin(), username, "Incorrect results");

        pumapiClientMockDelegate.assertNotInvoked().getUser(username);
    }

    @Test
    public void getGroupShouldInvokeDelegateOnColdCache() {
        // define behaviour
        String groupname = "some.group.not.yet.in.cache";
        PpmsGroup dummyGroup = new PpmsGroup();
        dummyGroup.setUnitlogin(groupname);
        pumapiClientMockDelegate.returns(dummyGroup).getGroup(groupname);

        // run test
        PpmsGroup result = cachingClient.getGroup(groupname);

        // assert results and invocations
        assertNotNull(result, "Non null results expected");
        assertEquals(result.getUnitlogin(), groupname, "Incorrect results");

        pumapiClientMockDelegate.assertInvoked().getGroup(groupname);
    }

    @Test
    public void getGroupShouldNotInvokeDelegateOnWarmCache() {
        // define behaviour
        String groupname = "some.group.already.in.cache";
        PpmsGroup dummyGroup = new PpmsGroup();
        dummyGroup.setUnitlogin(groupname);
        pumapiClientMockDelegate.returns(dummyGroup).getGroup(groupname);

        // warm-up cache
        cacheManager.getCache(CACHE_NAME).put(new Element("getGroup-" + groupname, dummyGroup));

        // run test
        PpmsGroup result = cachingClient.getGroup(groupname);

        // assert results and invocations
        assertNotNull(result, "Non null results expected");
        assertEquals(result.getUnitlogin(), groupname, "Incorrect results");

        pumapiClientMockDelegate.assertNotInvoked().getGroup(groupname);
    }

    @Test
    public void getSystemShouldInvokeDelegateOnColdCache() {
        // define behaviour
        Long systemId = 123L;
        PpmsSystem dummySystem = new PpmsSystem();
        dummySystem.setSystemId(systemId);
        pumapiClientMockDelegate.returns(dummySystem).getSystem(systemId);

        // run test
        PpmsSystem result = cachingClient.getSystem(systemId);

        // assert results and invocations
        assertNotNull(result, "Non null results expected");
        assertEquals(result.getSystemId(), systemId, "Incorrect results");

        pumapiClientMockDelegate.assertInvoked().getSystem(systemId);
    }

    @Test
    public void getSystemShoulNotInvokeDelegateOnWarmCache() {
        // define behaviour
        Long systemId = 123L;
        PpmsSystem dummySystem = new PpmsSystem();
        dummySystem.setSystemId(systemId);
        pumapiClientMockDelegate.returns(dummySystem).getSystem(systemId);

        // warm-up cache
        cacheManager.getCache(CACHE_NAME).put(new Element("getSystem-" + systemId, dummySystem));

        // run test
        PpmsSystem result = cachingClient.getSystem(systemId);

        // assert results and invocations
        assertNotNull(result, "Non null results expected");
        assertEquals(result.getSystemId(), systemId, "Incorrect results");

        pumapiClientMockDelegate.assertNotInvoked().getSystem(systemId);
    }

}
