/**
 *
 */
package org.imagopole.omero.auth;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.imagopole.ppms.api.dto.PpmsGroup;
import org.imagopole.ppms.api.dto.PpmsPrivilege;
import org.imagopole.ppms.api.dto.PpmsSystem;
import org.imagopole.ppms.api.dto.PpmsUser;
import org.imagopole.ppms.api.dto.PpmsUserPrivilege;


/**
 * @author seb
 *
 */
public final class TestsUtil {

    /** Default "protected" OMERO group names. */
    public static final List<String> OMERO_SYSTEM_GROUPS =
        Arrays.asList(new String[] { "system", "guest", "user", "default" });

    /** Test cases OMERO event. */
    public static final String TEST_EVENT_TYPE = "Test";

    /** Test cases agents source IP adress. */
    public static final String LOOPBACK_IPV4 = "127.0.0.1";

    /** Default naming prefix for PPMS instruments fixtures. */
    public static final String SYSTEM_PREFIX = "ppms_system_";

    /** Default naming prefix for PPMS groups fixtures. */
    public static final String UNIT_PREFIX = "ppms_unit_";

    /** Modified naming prefix for PPMS instruments sync fixtures. */
    public static final String WRANGLE_PREFIX = "ppms+";

    /** An inactive PPMS group/unit. */
    public static final PpmsGroup inactiveUnit(String unitLogin) {
        PpmsGroup unit = new PpmsGroup();
        unit.setUnitlogin(unitLogin);
        unit.setUnitname(unitName(unitLogin));
        return unit;
    }

    /** Modifies the experimenter fields. */
    public static final PpmsUser wrangleFields(PpmsUser user) {
        PpmsUser wrangledUser = new PpmsUser();
        wrangledUser.setLogin(user.getLogin());
        wrangledUser.setFname(wrangle(user.getFname()));
        wrangledUser.setLname(wrangle(user.getLname()));
        wrangledUser.setEmail(wrangle(user.getEmail()));
        return wrangledUser;
    }

    /** Simple user with first name and last name identical to login. */
    public static final PpmsUser newSimpleUser(String login, String email) {
        PpmsUser user = new PpmsUser();
        user.setLogin(login);
        user.setFname(login);
        user.setLname(login);
        user.setEmail(email);
        return user;
    }

    /** A user supposed missing in the OMERO and LDAP databases, and present in PPMS. */
    public static final PpmsUser newPpmsUser() {
        PpmsUser ppmsUnitUser = new PpmsUser();
        ppmsUnitUser.setLogin(PpmsUnit.DEFAULT_USER);
        ppmsUnitUser.setFname(PpmsUnit.DEFAULT_USER_GN);
        ppmsUnitUser.setLname(PpmsUnit.DEFAULT_USER_SN);
        ppmsUnitUser.setEmail(PpmsUnit.DEFAULT_USER_EMAIL);
        return ppmsUnitUser;
    }

    /** A user supposed missing in the OMERO and PPMS databases, and present in LDAP. */
    public static final PpmsUser newLdapUser() {
        PpmsUser ppmsUnitUser = new PpmsUser();
        ppmsUnitUser.setLogin(LdapUnit.DEFAULT_USER);
        ppmsUnitUser.setFname(LdapUnit.DEFAULT_USER_GN);
        ppmsUnitUser.setLname(LdapUnit.DEFAULT_USER_SN);
        ppmsUnitUser.setEmail(LdapUnit.DEFAULT_USER_EMAIL);
        return ppmsUnitUser;
    }

    /** A user supposed missing in the OMERO database, and present in LDAP and PPMS. */
    public static final PpmsUser newSharedUser() {
        PpmsUser sharedUser = new PpmsUser();
        sharedUser.setLogin(LdapUnit.PPMS_USER);
        sharedUser.setFname(LdapUnit.PPMS_USER_GN);
        sharedUser.setLname(LdapUnit.PPMS_USER_SN);
        sharedUser.setEmail(LdapUnit.PPMS_USER_EMAIL);
        return sharedUser;
    }

    /** Another user supposed missing in the OMERO database, and present in LDAP and PPMS. */
    public static final PpmsUser newSharedUserB() {
        PpmsUser sharedUser = new PpmsUser();
        sharedUser.setLogin(LdapUnit.PPMS_USER_B);
        sharedUser.setFname(LdapUnit.PPMS_USER_GN_B);
        sharedUser.setLname(LdapUnit.PPMS_USER_SN_B);
        sharedUser.setEmail(LdapUnit.PPMS_USER_EMAIL_B);
        return sharedUser;
    }

    /** A user supposed present in the OMERO, LDAP and PPMS databases. */
    public static final PpmsUser newKnownUser() {
        PpmsUser knownUser = new PpmsUser();
        knownUser.setLogin(OmeroUnit.KNOWN_USER);
        knownUser.setFname(OmeroUnit.KNOWN_USER_GN);
        knownUser.setLname(OmeroUnit.KNOWN_USER_SN);
        knownUser.setEmail(OmeroUnit.KNOWN_USER_EMAIL);
        return knownUser;
    }

    /**
     * A user supposed present in the OMERO and PPMS databases, but missing in LDAP - a.k.a "foo user"
     * as this should be a corner case (most users will be either fully local to OMERO or initialized
     * by the LDAP provider, then sync'd via PPMS).
     * However, this may happen when a user has been removed from LDAP (eg. departure) but is still
     * enabled in PPMS (provided that the PPMS-LDAP link has been switched back to a PPMS-local password).
     **/
    public static final PpmsUser newFooUser() {
        PpmsUser fooUser = new PpmsUser();
        fooUser.setLogin(PpmsUnit.OMERO_USER);
        fooUser.setFname(PpmsUnit.OMERO_USER_GN);
        fooUser.setLname(PpmsUnit.OMERO_USER_SN);
        fooUser.setEmail(PpmsUnit.OMERO_USER_EMAIL);
        return fooUser;
    }

    public static final PpmsUser activate(PpmsUser user) {
        if (null != user) {
            user.setActive(Boolean.TRUE);
        }
        return user;
    }

    /** {@link PpmsPrivilege.Deactivated} */
    public static final List<PpmsUserPrivilege> inactiveRights(long systemId) {
        return rightsList(systemId, PpmsPrivilege.Deactivated);
    }

    /** {@link PpmsPrivilege.Novice} */
    public static final List<PpmsUserPrivilege> noviceRights(long systemId) {
        return rightsList(systemId, PpmsPrivilege.Novice);
    }

    /** {@link PpmsPrivilege.Autonomous} */
    public static final List<PpmsUserPrivilege> autonomousRights(long systemId) {
        return rightsList(systemId, PpmsPrivilege.Autonomous);
    }

    /** {@link PpmsPrivilege.SuperUser} */
    public static final List<PpmsUserPrivilege> superUserRights(long systemId) {
        return rightsList(systemId, PpmsPrivilege.SuperUser);
    }

    /** Expose a single system privilege as a list. */
    public static List<PpmsUserPrivilege> rightsList(long systemId, PpmsPrivilege privilegeLevel) {
        List<PpmsUserPrivilege> result = new ArrayList<PpmsUserPrivilege>();
        PpmsUserPrivilege privilege = new PpmsUserPrivilege(systemId, privilegeLevel);
        result.add(privilege);
        return result;
    }

    /** An inactive PPMS system with no required autonomy. */
    public static PpmsSystem inactiveSystem(long systemId, String name) {
        PpmsSystem ppmsSystem = new PpmsSystem();
        ppmsSystem.setSystemId(systemId);
        ppmsSystem.setName(name);
        ppmsSystem.setType(PpmsUnit.SYSTEM_TYPE);
        ppmsSystem.setCoreFacilityRef(PpmsUnit.FACILITY_ID);
        return ppmsSystem;
    }

    /** An active PPMS system with no required autonomy. */
    public static final PpmsSystem activeSystem(long systemId, String name) {
        PpmsSystem ppmsSystem = inactiveSystem(systemId, name);
        ppmsSystem.setActive(Boolean.TRUE);
        return ppmsSystem;
    }

    /** An inactive PPMS  system, with no required autonomy and a default ID/facility ID. */
    public static final PpmsSystem inactiveSystem() {
        PpmsSystem ppmsSystem =
            inactiveSystem(PpmsUnit.INACTIVE_SYSTEM_ID, systemName(PpmsUnit.INACTIVE_SYSTEM_ID));
        return ppmsSystem;
    }

    /** An active PPMS system with no required autonomy and a default ID/facility ID. */
    public static final PpmsSystem newOpenSystem() {
        PpmsSystem ppmsSystem =
            activeSystem(PpmsUnit.OPEN_SYSTEM_ID, systemName(PpmsUnit.OPEN_SYSTEM_ID));
        return ppmsSystem;
    }

    /** A PPMS system which requires autonomy, and a default ID/facility ID.  */
    public static final PpmsSystem newRestrictedSystem() {
        PpmsSystem ppmsSystem =
            activeSystem(PpmsUnit.RESTRICTED_SYSTEM_ID, systemName(PpmsUnit.RESTRICTED_SYSTEM_ID));

        ppmsSystem.setAutonomyRequired(true);
        return ppmsSystem;
    }

    /** Default naming convention for PPMS instruments fixtures. */
    public static String systemName(long systemId) {
        return SYSTEM_PREFIX + systemId;
    }

    /** Default naming convention for PPMS groups fixtures. */
    public static String unitName(String unitLogin) {
        return UNIT_PREFIX + unitLogin;
    }

    /** Modified naming convention for PPMS instruments sync fixtures. */
    public static final String wrangle(String input) {
        String result = null;

        if (null != input) {

            result = WRANGLE_PREFIX.concat(input);

        }

        return result;
    }

    /**
     * Test fixtures data.
     *
     * @author seb
     *
     */
    public static final class Data {
        public static final String USERNAME = "some.username";
        public static final String PASSWORD = "some.password";
        public static final boolean GROUPS_STRICT_MODE = true;
        public static final boolean EXTERNAL_CONFIG_ENABLED = true;
        public static final boolean EXTERNAL_CONFIG_DISABLED = false;

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

        public static final String FLYWAY_DB_BASE_URL         = "flyway.db.base_url";
        public static final String FLYWAY_DB_INIT_ON_MIGRATE  = "flyway.db.init_on_migrate";
        public static final String FLYWAY_DB_CLEAN_ON_MIGRATE = "flyway.db.clean_on_migrate";
        public static final String FLYWAY_DB_MIGRATION_TARGET = "flyway.db.migration_target";
        public static final String FLYWAY_DB_LOCATIONS        = "flyway.db.locations";
        public static final String FLYWAY_LOCATIONS_SEPARATOR = ",";
        public static final String FLYWAY_DEFAULT_LOCATIONS   = "db/migration"
                                                                + FLYWAY_LOCATIONS_SEPARATOR
                                                                + "db/fixtures";

        public static final String PPMS_CONFIG               = "omero.ppms.config";
        public static final String PPMS_NEW_USER_GROUP       = "omero.ppms.new_user_group";
        public static final String PPMS_SYNC_GROUPS          = "omero.ppms.sync_groups";
        public static final String PPMS_SYNC_USER            = "omero.ppms.sync_user";
        public static final String PPMS_INCLUDE_FACILITIES   = "omero.ppms.include_facilities";
        public static final String PPMS_INCLUDE_SYSTEM_TYPES = "omero.ppms.include_system_types";

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
        public static final int COMMON_LDIF_MIN_ENTRIES = 6; // 1 dc + 1 ou + 4 users

        /** The "DEFAULT_USER" is assumed to be known to LDAP only, not to PPMS. */
        public static final String DEFAULT_USER = "jdoe";
        public static final String DEFAULT_PWD = "ldapunit";
        public static final String DEFAULT_USER_GN = "John";
        public static final String DEFAULT_USER_SN = "DOE";
        public static final String DEFAULT_USER_EMAIL = "john.doe@example.com";
        public static final String DEFAULT_USER_DN = "uid=jdoe,ou=People,dc=example,dc=com";
        public static final String DEFAULT_GROUP = "LdapUnitDefault";

        /** The "PPMS_USER" is assumed to be known to both LDAP and PPMS. */
        public static final String PPMS_USER = "fbloggs";
        public static final String PPMS_PWD = "bothunit";
        public static final String PPMS_USER_GN = "Fred";
        public static final String PPMS_USER_SN = "BLOGGS";
        public static final String PPMS_USER_EMAIL = "fred.bloggs@example.com";
        public static final String PPMS_USER_DN = "uid=fbloggs,ou=People,dc=example,dc=com";

        /** The "PPMS_USER" is assumed to be known to both LDAP and PPMS. */
        public static final String PPMS_USER_B = "kbloggs";
        public static final String PPMS_PWD_B = "bothunit";
        public static final String PPMS_USER_GN_B = "Karl";
        public static final String PPMS_USER_SN_B = "BLOGGS";
        public static final String PPMS_USER_EMAIL_B = "karl.bloggs@example.com";
        public static final String PPMS_USER_DN_B = "uid=kbloggs,ou=People,dc=example,dc=com";

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

        /** The "DEFAULT_USER" is assumed to be known to PPMS only, not to LDAP. */
        public static final String DEFAULT_USER = "jbar";
        public static final String DEFAULT_PWD = "ppmsunit";
        public static final String DEFAULT_USER_GN = "Joe";
        public static final String DEFAULT_USER_SN = "BAR";
        public static final String DEFAULT_USER_EMAIL = "joe.bar@sofar.net";
        public static final String DEFAULT_GROUP = "PpmsUnitDefault";

        /** The "OMERO_USER" is assumed to be known to PPMS and OMERO, not to LDAP. */
        public static final String OMERO_USER = "foo.doo";
        public static final String OMERO_PWD = "should-not-auth-via-jdbc";
        public static final String OMERO_USER_GN = "Foo";
        public static final String OMERO_USER_SN = "DOO";
        public static final String OMERO_USER_EMAIL = "foo.doo@corner.net";
        public static final String OMERO_GROUP = "?";

        public static final long OPEN_SYSTEM_ID = 111L;
        public static final long DUPLICATE_SYSTEM_ID = 222L;
        public static final long RESTRICTED_SYSTEM_ID = 333L;
        public static final long INACTIVE_SYSTEM_ID = 444L;
        public static final long FACILITY_ID = 22L;
        public static final String SYSTEM_TYPE = "some.system.type";
        public static final String UNIT_LOGIN = "some.unit.login";

        public static final String AUTONOMY_GROUP_BEAN = ":bean:ppmsSystemAutonomyToGroupBean";
        public static final String SYSTEM_GROUP_BEAN = ":bean:ppmsSystemToGroupBean";
        public static final String FACILITIES_WHITELIST = "," + FACILITY_ID;
        public static final String SYSTEM_TYPES_WHITELIST = SYSTEM_TYPE + ",";

        /** Private constructor (utility class) */
        private PpmsUnit() {
            super();
        }
    }

    /**
     * Constants for the "OmeroUnit" integration tests.
     *
     * Values must be kept in sync with those defined in OMERO integration test db.
     */
    public static final class OmeroUnit {

        public static final String GUEST_USER_GN = "Guest";
        public static final String GUEST_USER_SN = "Account";
        public static final String GUEST_USER_PWD = "anything";
        public static final String ROOT_USER_PWD = "root_dbunit";

        /** The "DEFAULT_USER" is assumed to be known to OMERO only, not to PPMS or LDAP. */
        public static final String DEFAULT_USER = "otto_sepp";
        public static final String DEFAULT_PWD = "dbunit";
        public static final String DEFAULT_USER_GN = "Otto";
        public static final String DEFAULT_USER_SN = "SEPP";
        public static final String DEFAULT_GROUP = "OmeroUnitLocal";

        /** The "KNOWN_USER" is assumed to be known to both LDAP and PPMS. */
        public static final String KNOWN_USER = "jbloggs";
        public static final String KNOWN_PWD = "omerounit";
        public static final String KNOWN_USER_GN = "Joe";
        public static final String KNOWN_USER_SN = "BLOGGS";
        public static final String KNOWN_USER_EMAIL = "joe.bloggs@example.com";
        public static final String KNOWN_USER_DN = "uid=jbloggs,ou=People,dc=example,dc=com";
        public static final String PPMS_DUPLICATE_GROUP = "OmeroUnitPpmsDuplicate";

        /** Private constructor (utility class) */
        private OmeroUnit() {
            super();
        }
    }

    /** Private constructor (utility class) */
    private TestsUtil() {
        super();
    }

}
