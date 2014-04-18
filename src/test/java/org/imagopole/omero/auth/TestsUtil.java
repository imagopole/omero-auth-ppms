/**
 *
 */
package org.imagopole.omero.auth;

import java.util.Arrays;
import java.util.List;

import ome.model.internal.Permissions;

import org.imagopole.ppms.api.dto.PpmsGroup;


/**
 * @author seb
 *
 */
public class TestsUtil {

    public static final List<String> OMERO_SYSTEM_GROUPS =
        Arrays.asList(new String[] { "system", "guest", "user", "default" });

    public static final String TEST_EVENT_TYPE = "Test";

    public static final PpmsGroup newUnit(String name) {
        PpmsGroup unit = new PpmsGroup();
        unit.setUnitname(name);
        unit.setUnitlogin("testng::" + name);

        return unit;
    }

    // test fixtures data
    public static final class Data {
        public static final String USERNAME = "some.username";
        public static final String PASSWORD = "some.password";
        public static final boolean GROUPS_STRICT_MODE = true;
        public static final Permissions PERMISSIONS_FOR_LEVEL = Permissions.USER_PRIVATE;

        /** Private constructor (utility class) */
        private Data() {
            super();
        }
    }

    /**
     * Test groups.
     *
     * @author seb
     *
     */
    public static final class Groups {

        public static final String INTEGRATION = "integration";
        public static final String BROKEN = "broken";

        /** Private constructor (utility class) */
        private Groups() {
            super();
        }
    }

    /**
     * Environment variables keys for tests lookups.
     *
     * @author seb
     *
     */
    public static final class Env {

        public static final String OMERO_CONFIG = "OMERO_CONFIG";
        public static final String OMERO_CONFIG_LOCATION = "omero.config.location";

        public static final String OMERO_DB_NAME = "omero.db.name";
        public static final String OMERO_DB_USER = "omero.db.user";
        public static final String OMERO_DB_PASS = "omero.db.pass";
        public static final String FLYWAY_DB_BASE_URL = "flyway.db.base_url";
        public static final String FLYWAY_DB_INIT_ON_MIGRATE = "flyway.db.init_on_migrate";
        public static final String FLYWAY_DB_CLEAN_ON_MIGRATE = "flyway.db.clean_on_migrate";

        /** Private constructor (utility class) */
        private Env() {
            super();
        }
    }

    /**
     * Constants for the "LdapUnit" integration tests.
     *
     * Values must be kept in sync with those defined in the LDIF fixtures and the config settings
     * exposed via omero-local[-template].properties.
     */
    public static final class LdapUnit {

        public static final int LISTEN_PORT = 10389;
        public static final String BASE_DN = "dc=example,dc=com";
        public static final String COMMON_LDIF_LOCATION = "ldap/migration/common.ldif";
        public static final int COMMON_LDIF_MIN_ENTRIES = 3; // 1 dc + 1 ou + 1 user

        public static final String DEFAULT_USER = "jdoe";
        public static final String DEFAULT_PWD = "ldapunit";
        public static final String DEFAULT_USER_GN = "John";
        public static final String DEFAULT_USER_SN = "DOE";
        public static final String DEFAULT_USER_EMAIL = "john.doe@example.com";
        public static final String DEFAULT_USER_DN = "uid=jdoe,ou=People,dc=example,dc=com";
        public static final String DEFAULT_GROUP = "LdapUnitDefault";

        /** Private constructor (utility class) */
        private LdapUnit() {
            super();
        }
    }

    /**
     * Constants for the "PpmsUnit" integration tests.
     *
     * Values must be kept in sync with those defined in the config settings exposed via
     * omero-local[-template].properties.
     */
    public static final class PpmsUnit {

        public static final String DEFAULT_USER = "jbar";
        public static final String DEFAULT_PWD = "ppmsunit";
        public static final String DEFAULT_USER_GN = "Joe";
        public static final String DEFAULT_USER_SN = "BAR";
        public static final String DEFAULT_USER_EMAIL = "joe.bar@sofar.net";
        public static final String DEFAULT_GROUP = "PpmsUnitDefault";

        /** Private constructor (utility class) */
        private PpmsUnit() {
            super();
        }
    }

    /** Private constructor (utility class) */
    private TestsUtil() {
        super();
    }

}
