/**
 *
 */
package org.imagopole.omero.auth.impl.ppms;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import ome.security.auth.PasswordProvider;

import org.databene.contiperf.PerfTest;
import org.databene.contiperf.Required;
import org.databene.contiperf.timer.ConstantTimer;
import org.imagopole.omero.auth.BenchUtil;
import org.imagopole.omero.auth.BenchUtil.TestKeys;
import org.imagopole.omero.auth.impl.AbstractOmeroServerBenchTest;
import org.junit.Before;
import org.junit.Test;

/**
 * @author seb
 *
 */
public class PpmsPasswordProvidersBenchTest extends AbstractOmeroServerBenchTest {

    /** PPMS standalone password provider (PPMS only). */
    private PasswordProvider ppmsStandalonePasswordProvider;

    /** PPMS "dual auth" password provider (PPMS + LDAP). */
    private PasswordProvider ppmsLdapChainedPasswordProvider;

    /** @see TestKeys#LDAP_USERNAME.
     *  Note: must be an existing account in OMERO, to bench against the password validation logic only. */
    private String ldapUserName;

    /** @see TestKeys#LDAP_PWD_OK */
    private String ldapRightPassword;

    /** @see TestKeys#LDAP_PWD_KO */
    private String ldapWrongPassword;

    @Before
    public void setUp() {
        // spring beans
        ppmsStandalonePasswordProvider = (PasswordProvider) omeroContext.getBean("ppmsPasswordProvider");
        ppmsLdapChainedPasswordProvider = (PasswordProvider) omeroContext.getBean("ppmsLdapChainedPasswordProvider431");

        // config settings
        ldapUserName = configProperties.getProperty(TestKeys.LDAP_USERNAME);
        ldapRightPassword = configProperties.getProperty(TestKeys.LDAP_PWD_OK);
        ldapWrongPassword = configProperties.getProperty(TestKeys.LDAP_PWD_KO);
    }

    @Test
    @PerfTest(invocations = BenchUtil.ACCOUNT_LOCKING_SAFE_ITERATIONS,
              timer = ConstantTimer.class, timerParams = { BenchUtil.WAIT_DEFAULT })
    @Required(max = 500, median = 500, percentile90 = 500, percentile95 = 500)
    public void standaloneLdapAuth() {
        Boolean success = ppmsStandalonePasswordProvider.checkPassword(ldapUserName, ldapRightPassword, true);
        assertNotNull("config should be enabled", success);
        assertTrue("should auth ok", success);
    }

    @Test
    @PerfTest(invocations = BenchUtil.ACCOUNT_LOCKING_SAFE_ITERATIONS,
              timer = ConstantTimer.class, timerParams = { BenchUtil.WAIT_DEFAULT })
    @Required(max = 500, median = 500, percentile90 = 500, percentile95 = 500)
    public void standaloneLdapNoAuth() {
        Boolean success = ppmsStandalonePasswordProvider.checkPassword(ldapUserName, ldapWrongPassword, true);
        assertNotNull("config should be enabled", success);
        assertFalse("should auth ko", success);
    }

    @Test
    @PerfTest(invocations = BenchUtil.ITERATIONS_DEFAULT,
              timer = ConstantTimer.class, timerParams = { BenchUtil.WAIT_DEFAULT })
    @Required(max = 500, median = 500, percentile90 = 500, percentile95 = 500)
    public void chainedLdapAuth() {
        Boolean success = ppmsLdapChainedPasswordProvider.checkPassword(ldapUserName, ldapRightPassword, true);
        assertNotNull("config should be enabled", success);
        assertTrue("should auth ok", success);
    }

    @Test
    @PerfTest(invocations = BenchUtil.ACCOUNT_LOCKING_SAFE_ITERATIONS,
              timer = ConstantTimer.class, timerParams = { BenchUtil.WAIT_DEFAULT })
    @Required(max = 500, median = 500, percentile90 = 500, percentile95 = 500)
    public void chainedLdapNoAuth() {
        Boolean success = ppmsLdapChainedPasswordProvider.checkPassword(ldapUserName, ldapWrongPassword, true);
        assertNotNull("config should be enabled", success);
        assertFalse("should auth ko", success);
    }

}
