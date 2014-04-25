package org.imagopole.omero.auth.impl;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.imagopole.omero.auth.api.ExternalAuthConfig;
import org.imagopole.omero.auth.impl.DefaultExternalAuthConfig.ConfigKeys;
import org.testng.annotations.Test;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertNull;
import static org.testng.Assert.assertTrue;

public class DefaultExternalAuthConfigTest {

    @Test
    public void shortConstructorShouldConvertNullConfigMapToEmptyMap() {
        ExternalAuthConfig config = new DefaultExternalAuthConfig(true, "some-group-spec");
        Map<String, Object> map = config.getConfigMap();

        assertNotNull(map, "Non-null configMap expected");
        assertTrue(map.isEmpty(), "Empty configMap expected");
    }

    @Test
    public void fullConstructorShouldConvertNullConfigMapToEmptyMap() {
        ExternalAuthConfig config =
            new DefaultExternalAuthConfig(true, "some-group-spec", true, true, null);
        Map<String, Object> map = config.getConfigMap();

        assertNotNull(map, "Non-null configMap expected");
        assertTrue(map.isEmpty(), "Empty configMap expected");
    }

    @Test(expectedExceptions = UnsupportedOperationException.class)
    public void shortConstructorShouldReturnImmutableConfigMap() {
        ExternalAuthConfig config = new DefaultExternalAuthConfig(true, "some-group-spec");
        Map<String, Object> map = config.getConfigMap();

        assertNotNull(map, "Non-null configMap expected");
        map.put("putting-key-value", "should-fail");
    }

    @Test(expectedExceptions = UnsupportedOperationException.class)
    public void fullConstructorShouldReturnImmutableConfigMap() {
        ExternalAuthConfig config =
            new DefaultExternalAuthConfig(true, "some-group-spec", true, true, new HashMap<String, Object>());
        Map<String, Object> map = config.getConfigMap();

        assertNotNull(map, "Non-null configMap expected");
        map.put("putting-key-value", "should-fail");
    }

    @Test
    public void shortConstructorShouldConvertNullEnabledToFalse() {
        ExternalAuthConfig config = new DefaultExternalAuthConfig(null, "some-group-spec");
        boolean enabled = config.isEnabled();

        assertFalse(enabled, "False Boolean expected");
    }

    @Test
    @SuppressWarnings("unchecked")
    public void fullConstructorShouldConvertNullEnabledToFalse() {
        ExternalAuthConfig config =
            new DefaultExternalAuthConfig(null, "some-group-spec", true, true, Collections.EMPTY_MAP);
        boolean enabled = config.isEnabled();

        assertFalse(enabled, "False Boolean expected");
    }

    @Test
    public void shortConstructorShouldConvertNullSyncToFalse() {
        ExternalAuthConfig config = new DefaultExternalAuthConfig(true, "some-group-spec");
        boolean syncGroups = config.syncGroupsOnLogin();
        boolean syncUser = config.syncUserOnLogin();

        assertFalse(syncGroups, "False Boolean expected");
        assertFalse(syncUser, "False Boolean expected");
    }

    @Test
    @SuppressWarnings("unchecked")
    public void fullConstructorShouldConvertNullSyncToFalse() {
        ExternalAuthConfig config =
            new DefaultExternalAuthConfig(true, "some-group-spec", null, null, Collections.EMPTY_MAP);
        boolean syncGroups = config.syncGroupsOnLogin();
        boolean syncUser = config.syncUserOnLogin();

        assertFalse(syncGroups, "False Boolean expected");
        assertFalse(syncUser, "False Boolean expected");
    }

    @Test
    public void shortConstructorShouldDefaultSyncGroupsToNullSyncOnLogin() {
        ExternalAuthConfig config = new DefaultExternalAuthConfig(true, "some-group-spec");
        boolean syncGroups = config.syncGroupsOnLogin();

        assertFalse(syncGroups, "False Boolean expected");
    }

    @Test
    public void shortConstructorShouldDefaultSyncGroupsToFalseSync() {
        ExternalAuthConfig config = new DefaultExternalAuthConfig(true, "some-group-spec");
        boolean syncGroups = config.syncGroupsOnLogin();
        boolean syncUser = config.syncUserOnLogin();

        assertFalse(syncGroups, "False Boolean expected");
        assertFalse(syncUser, "False Boolean expected");
    }

    @Test
    @SuppressWarnings("unchecked")
    public void fullConstructorShouldConvertNullSyncGroupsToFalse() {
        ExternalAuthConfig config =
            new DefaultExternalAuthConfig(true, "some-group-spec", null, true, Collections.EMPTY_MAP);
        boolean syncGroups = config.syncGroupsOnLogin();

        assertFalse(syncGroups, "False Boolean expected");
    }

    @Test
    public void shortConstructorShouldDefaultSyncUserToNullSyncOnLogin() {
        ExternalAuthConfig config = new DefaultExternalAuthConfig(true, "some-group-spec");
        boolean syncUser = config.syncUserOnLogin();

        assertFalse(syncUser, "False Boolean expected");
    }

    @Test
    public void shortConstructorShouldDefaultSyncUserToFalseSyncOnLogin() {
        ExternalAuthConfig config = new DefaultExternalAuthConfig(true, "some-group-spec");
        boolean syncUser = config.syncUserOnLogin();

        assertFalse(syncUser, "False Boolean expected");
    }

    @Test
    @SuppressWarnings("unchecked")
    public void fullConstructorShouldConvertNullSyncUserToFalse() {
        ExternalAuthConfig config =
            new DefaultExternalAuthConfig(true, "some-group-spec", true, null, Collections.EMPTY_MAP);
        boolean syncUser = config.syncUserOnLogin();

        assertFalse(syncUser, "False Boolean expected");
    }

    @Test
    public void shortConstructorShouldNotConvertNullGroupSpec() {
        ExternalAuthConfig config = new DefaultExternalAuthConfig(true, null);
        String groupSpec = config.getNewUserGroup();

        assertNull(groupSpec, "Null groupSpec expected");
    }

    @Test
    @SuppressWarnings("unchecked")
    public void fullConstructorShouldNotConvertNullGroupSpec() {
        ExternalAuthConfig config =
            new DefaultExternalAuthConfig(true, null, true, true, Collections.EMPTY_MAP);
        String groupSpec = config.getNewUserGroup();

        assertNull(groupSpec, "Null groupSpec expected");
    }

    @Test
    public void shortConstructorShouldNullifyBlankGroupSpec() {
        ExternalAuthConfig config = new DefaultExternalAuthConfig(true, "  ");
        String groupSpec = config.getNewUserGroup();

        assertNull(groupSpec, "Null groupSpec expected");
    }

    @Test
    @SuppressWarnings("unchecked")
    public void fullConstructorShouldNullifyBlankGroupSpec() {
        ExternalAuthConfig config =
            new DefaultExternalAuthConfig(true, "  ", true, true, Collections.EMPTY_MAP);
        String groupSpec = config.getNewUserGroup();

        assertNull(groupSpec, "Null groupSpec expected");
    }

    @Test
    public void shortConstructorShouldTrimGroupSpec() {
        ExternalAuthConfig config = new DefaultExternalAuthConfig(true, " some-group-spec ");
        String groupSpec = config.getNewUserGroup();

        assertEquals(groupSpec, "some-group-spec", "Incorrect groupSpec");
    }

    @Test
    @SuppressWarnings("unchecked")
    public void fullConstructorShouldTrimGroupSpec() {
        ExternalAuthConfig config =
            new DefaultExternalAuthConfig(true, " some-group-spec ", true, true, Collections.EMPTY_MAP);
        String groupSpec = config.getNewUserGroup();

        assertEquals(groupSpec, "some-group-spec", "Incorrect groupSpec");
    }

    @Test
    public void listExcludedGroupsShouldReturnEmpyListByDefault() {
        ExternalAuthConfig config =
            new DefaultExternalAuthConfig(true, "some-group-spec", true, true, null);

        List<String> result = config.listExcludedGroups();

        assertNotNull(result, "Non-null result expected");
        assertTrue(result.isEmpty(), "Empty result expected");
    }

    @Test
    public void listExcludedUsersShouldReturnEmpyListByDefault() {
        ExternalAuthConfig config =
            new DefaultExternalAuthConfig(true, "some-group-spec", true, true, null);

        List<String> result = config.listExcludedUsers();

        assertNotNull(result, "Non-null result expected");
        assertTrue(result.isEmpty(), "Empty result expected");
    }

    @Test
    public void failOnDuplicateGroupsShouldReturnFalseByDefault() {
        ExternalAuthConfig config =
            new DefaultExternalAuthConfig(true, "some-group-spec", true, true, null);

        boolean result = config.failOnDuplicateGroups();

        assertFalse(result, "False result expected");
    }

    @Test
    public void listExcludedGroupsFoundTest() {
        Map<String, Object> fixture = new HashMap<String, Object>();
        List<String> expected = Arrays.asList(new String[]{ "root-group" });
        fixture.put(ConfigKeys.EXCLUDE_GROUPS, expected);

        ExternalAuthConfig config =
            new DefaultExternalAuthConfig(true, "some-group-spec", true, true, fixture);

        List<String> result = config.listExcludedGroups();

        assertNotNull(result, "Non-null result expected");
        assertFalse(result.isEmpty(), "Non empty result expected");
        assertEquals(result, expected, "Incorrect result");
    }

    @Test
    public void listExcludedUsersFoundTest() {
        Map<String, Object> fixture = new HashMap<String, Object>();
        List<String> expected = Arrays.asList(new String[]{ "guest-user" });
        fixture.put(ConfigKeys.EXCLUDE_USERS, expected);

        ExternalAuthConfig config =
            new DefaultExternalAuthConfig(true, "some-group-spec", true, true, fixture);

        List<String> result = config.listExcludedUsers();

        assertNotNull(result, "Non-null result expected");
        assertFalse(result.isEmpty(), "Non empty result expected");
        assertEquals(result, expected, "Incorrect result");
    }

    @Test
    public void listExcludedGroupsNotFoundTest() {
        Map<String, Object> fixture = new HashMap<String, Object>();
        List<String> excluded = Arrays.asList(new String[]{ "root-group" });
        fixture.put("some.invalid.key", excluded);

        ExternalAuthConfig config =
            new DefaultExternalAuthConfig(true, "some-group-spec", true, true, fixture);

        List<String> result = config.listExcludedGroups();

        assertNotNull(result, "Non-null result expected");
        assertTrue(result.isEmpty(), "Empty result expected");
    }

    @Test
    public void listExcludedUsersNotFoundTest() {
        Map<String, Object> fixture = new HashMap<String, Object>();
        List<String> excluded = Arrays.asList(new String[]{ "guest-user" });
        fixture.put("some.invalid.key", excluded);

        ExternalAuthConfig config =
            new DefaultExternalAuthConfig(true, "some-group-spec", true, true, fixture);

        List<String> result = config.listExcludedGroups();

        assertNotNull(result, "Non-null result expected");
        assertTrue(result.isEmpty(), "Empty result expected");
    }

    @Test
    public void failOnDuplicateGroupsFoundTest() {
        Map<String, Object> fixture = new HashMap<String, Object>();
        fixture.put(ConfigKeys.FAIL_ON_DUPLICATE_GROUPS, "true");

        ExternalAuthConfig config =
            new DefaultExternalAuthConfig(true, "some-group-spec", true, true, fixture);

        boolean result = config.failOnDuplicateGroups();

        assertTrue(result, "Incorrect result");
    }

    @Test
    public void failOnDuplicateGroupsNotFoundTest() {
        Map<String, Object> fixture = new HashMap<String, Object>();
        fixture.put("some.invalid.key", "true");

        ExternalAuthConfig config =
            new DefaultExternalAuthConfig(true, "some-group-spec", true, true, fixture);

        boolean result = config.failOnDuplicateGroups();

        assertFalse(result, "Incorrect result");
    }

}
