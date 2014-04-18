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

    public static final PpmsGroup newUnit(String name) {
        PpmsGroup unit = new PpmsGroup();
        unit.setUnitname(name);
        unit.setUnitlogin("testng::" + name);

        return unit;
    }

    // test fixtures data
    public final static class Data {
        public final static String USERNAME = "some.username";
        public final static String PASSWORD = "some.password";
        public final static boolean GROUPS_STRICT_MODE = true;
        public final static Permissions PERMISSIONS_FOR_LEVEL = Permissions.USER_PRIVATE;

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
    public final static class Groups {

        public final static String INTEGRATION = "integration";
        public final static String BROKEN = "broken";

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
    public final static class Env {

        public final static String OMERO_CONFIG = "OMERO_CONFIG";
        public final static String OMERO_CONFIG_LOCATION = "omero.config.location";

        public final static String OMERO_DB_NAME = "omero.db.name";
        public final static String OMERO_DB_USER = "omero.db.user";
        public final static String OMERO_DB_PASS = "omero.db.pass";
        public final static String FLYWAY_DB_BASE_URL = "flyway.db.base_url";
        public final static String FLYWAY_DB_INIT_ON_MIGRATE = "flyway.db.init_on_migrate";
        public final static String FLYWAY_DB_CLEAN_ON_MIGRATE = "flyway.db.clean_on_migrate";

        /** Private constructor (utility class) */
        private Env() {
            super();
        }
    }

    public final static class LdapUnit {

        public final static int LISTEN_PORT = 10389;
        public final static String BASE_DN = "dc=example,dc=com";
        public final static String COMMON_LDIF_LOCATION = "ldap/migration/common.ldif";
        // dc + ou + user
        public final static int COMMON_LDIF_MIN_ENTRIES = 3;

        /** Private constructor (utility class) */
        private LdapUnit() {
            super();
        }
    }

    /** Private constructor (utility class) */
    private TestsUtil() {
        super();
    }

}
