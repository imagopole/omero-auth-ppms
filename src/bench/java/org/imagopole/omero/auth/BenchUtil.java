/**
 *
 */
package org.imagopole.omero.auth;



/**
 * @author seb
 *
 */
public class BenchUtil {

    /** Default number of invocations to run perf tests. */
    public final static int ITERATIONS_DEFAULT = 10;

    public final static int ACCOUNT_LOCKING_SAFE_ITERATIONS = 1;

    /** Default wait time between invocations in milliseconds. */
    public final static int WAIT_DEFAULT = 500;

    /**
     * Environment variables keys for tests lookups.
     *
     * @author seb
     *
     */
    public final static class Env {

        public final static String BENCH_CONFIG = "BENCH_CONFIG";
        public final static String BENCH_CONFIG_LOCATION = "bench.config.location";

        /** Private constructor (utility class) */
        private Env() {
            super();
        }
    }

    /**
     * Extra configuration keys/values dedicated to integration testing.
     * @author seb
     *
     */
    public static class TestKeys {
        /** PPMS user name for LDAP user */
        public final static String LDAP_USERNAME = "bench.ppms.ldap_user";

        /** PPMS user name for local user */
        public final static String LOCAL_USERNAME = "bench.ppms.local_user";

        /** PPMS user name for unknown user */
        public final static String UNKNOWN_USERNAME = "bench.ppms.missing_user";

        /** PPMS ID for existing system */
        public final static String SYSTEM_ID = "bench.ppms.system_id";

        /** PPMS ID for unknown system */
        public final static String UNKNOWN_SYSTEM_ID = "bench.ppms.missing_system_id";

        /** PPMS group key for existing group */
        public final static String GROUP_KEY = "bench.ppms.group_key";

        /** PPMS group key for unknown group */
        public final static String UNKNOWN_GROUP_KEY = "bench.ppms.missing_group_key";

        /** Auth success for LDAP user */
        public final static String LDAP_PWD_OK = "bench.ppms.ldap_pwd_ok";

        /** Auth failure for LDAP user */
        public final static String LDAP_PWD_KO = "bench.ppms.ldap_pwd_ko";

        /** Auth success for local user */
        public final static String LOCAL_PWD_OK = "bench.ppms.local_pwd_ok";

        /** Auth failure for local user */
        public final static String LOCAL_PWD_KO = "bench.ppms.local_pwd_ko";

        /** Private constructor (utility class) */
        private TestKeys() {
            super();
        }
    }

    /** Private constructor (utility class) */
    private BenchUtil() {
        super();
    }

}
