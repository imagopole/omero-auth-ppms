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

        /** Private constructor (utility class) */
        private Env() {
            super();
        }
    }

    /** Private constructor (utility class) */
    private TestsUtil() {
        super();
    }

}
