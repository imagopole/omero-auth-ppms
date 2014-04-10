package org.imagopole.omero.auth.impl.ppms;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertNull;
import static org.testng.Assert.assertTrue;

import java.util.Arrays;
import java.util.List;

import net.sf.ehcache.CacheManager;
import net.sf.ehcache.Element;

import org.imagopole.omero.auth.TestsUtil.Data;
import org.imagopole.ppms.api.PumapiClient;
import org.imagopole.ppms.api.dto.PpmsGroup;
import org.imagopole.ppms.api.dto.PpmsSystem;
import org.imagopole.ppms.api.dto.PpmsUser;
import org.imagopole.ppms.api.dto.PpmsUserPrivilege;
import org.imagopole.ppms.api.dto.PumapiParams.PpmsSystemPrivilege;
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
    public void getUsersShouldNotCache() {
        // define behaviour
        List<String> fixture = Arrays.asList(new String[] { Data.USERNAME });
        pumapiClientMockDelegate.returns(fixture).getUsers(Boolean.TRUE);

        // run test
        List<String> result = cachingClient.getUsers(Boolean.TRUE);

        // check cache content
        Element cachedValue = cacheManager.getCache(CACHE_NAME).get("getUsers-true");

        // assert results and invocations
        assertNotNull(result, "Non null results expected");
        assertEquals(result.size(), 1, "Incorrect results");
        assertNull(cachedValue, "Null result expected");

        pumapiClientMockDelegate.assertInvoked().getUsers(Boolean.TRUE);
    }

    @Test
    public void getUserRightsShouldNotCache() {
        // define behaviour
        String username = Data.USERNAME;
        List<PpmsUserPrivilege> fixture =
            Arrays.asList(new PpmsUserPrivilege[] { new PpmsUserPrivilege(555L, PpmsSystemPrivilege.Novice) });
        pumapiClientMockDelegate.returns(fixture).getUserRights(username);

        // run test
        List<PpmsUserPrivilege> result = cachingClient.getUserRights(username);

        // check cache content
        Element cachedValue = cacheManager.getCache(CACHE_NAME).get("getUserRights-" + username);

        // assert results and invocations
        assertNotNull(result, "Non null results expected");
        assertEquals(result.size(), 1, "Incorrect results");
        assertNull(cachedValue, "Null result expected");

        pumapiClientMockDelegate.assertInvoked().getUserRights(username);
    }

    @Test
    public void authenticateShouldNotCache() {
        // define behaviour
        String username = Data.USERNAME;
        String password = "pwd";
        pumapiClientMockDelegate.returns(true).authenticate(username, password);

        // run test
        boolean result = cachingClient.authenticate(username, password);

        // check cache content
        Element cachedValue = cacheManager.getCache(CACHE_NAME).get("authenticate" + username);

        // assert results and invocations
        assertNotNull(result, "Non null results expected");
        assertTrue(result, "Incorrect result");
        assertNull(cachedValue, "Null result expected");

        pumapiClientMockDelegate.assertInvoked().authenticate(username, password);
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

        // check cache content
        Element cachedValue = cacheManager.getCache(CACHE_NAME).get("getUser-" + username);

        // assert results and invocations
        assertNotNull(result, "Non null results expected");
        assertEquals(result.getLogin(), username, "Incorrect results");
        assertNotNull(cachedValue, "Non null result expected");
        PpmsUser cachedUser = (PpmsUser) cachedValue.getObjectValue();
        assertEquals(cachedUser.getLogin(), username, "Incorrect results");

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
    public void getUserShouldNotCacheNullElements() {
        // define behaviour
        String username = "some.user.not.found";
        pumapiClientMockDelegate.returns(null).getUser(username);

        // run test
        PpmsUser result = cachingClient.getUser(username);

        // check cache content
        Element cachedValue = cacheManager.getCache(CACHE_NAME).get("getUser-" + username);

        // assert results and invocations
        assertNull(result, "Null result expected");
        assertNull(cachedValue, "Null result expected");

        pumapiClientMockDelegate.assertInvoked().getUser(username);
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

        // check cache content
        Element cachedValue = cacheManager.getCache(CACHE_NAME).get("getGroup-" + groupname);

        // assert results and invocations
        assertNotNull(result, "Non null results expected");
        assertEquals(result.getUnitlogin(), groupname, "Incorrect results");
        assertNotNull(cachedValue, "Non null result expected");
        PpmsGroup cachedGroup = (PpmsGroup) cachedValue.getObjectValue();
        assertEquals(cachedGroup.getUnitlogin(), groupname, "Incorrect results");

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
    public void getGroupShouldNotCacheNullElements() {
        // define behaviour
        String groupname = "some.group.not.found";
        pumapiClientMockDelegate.returns(null).getGroup(groupname);

        // run test
        PpmsGroup result = cachingClient.getGroup(groupname);

        // check cache content
        Element cachedValue = cacheManager.getCache(CACHE_NAME).get("getGroup-" + groupname);

        // assert results and invocations
        assertNull(result, "Null result expected");
        assertNull(cachedValue, "Null result expected");

        pumapiClientMockDelegate.assertInvoked().getGroup(groupname);
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

        // check cache content
        Element cachedValue = cacheManager.getCache(CACHE_NAME).get("getSystem-" + systemId);

        // assert results and invocations
        assertNotNull(result, "Non null results expected");
        assertEquals(result.getSystemId(), systemId, "Incorrect results");
        assertNotNull(cachedValue, "Non null result expected");
        PpmsSystem cachedSystem = (PpmsSystem) cachedValue.getObjectValue();
        assertEquals(cachedSystem.getSystemId(), systemId, "Incorrect results");

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

    @Test
    public void getSystemShoulNotCacheNullElements() {
        // define behaviour
        Long systemId = 999L;
        pumapiClientMockDelegate.returns(null).getSystem(systemId);

        // run test
        PpmsSystem result = cachingClient.getSystem(systemId);

        // check cache content
        Element cachedValue = cacheManager.getCache(CACHE_NAME).get("getSystem-" + systemId);

        // assert results and invocations
        assertNull(result, "Null result expected");
        assertNull(cachedValue, "Null result expected");

        pumapiClientMockDelegate.assertInvoked().getSystem(systemId);
    }

}
