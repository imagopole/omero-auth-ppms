/**
 *
 */
package org.imagopole.omero.auth.impl.ppms.user;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.databene.contiperf.PerfTest;
import org.databene.contiperf.Required;
import org.databene.contiperf.timer.ConstantTimer;
import org.imagopole.omero.auth.BenchUtil;
import org.imagopole.omero.auth.BenchUtil.TestKeys;
import org.imagopole.omero.auth.api.user.ExternalNewUserService;
import org.imagopole.omero.auth.impl.AbstractOmeroServerBenchTest;
import org.junit.Before;
import org.junit.Test;

/**
 * @author seb
 *
 */
public class PpmsExternalNewUserServiceBenchTest extends AbstractOmeroServerBenchTest {

    /** PPMS new user service bean. */
    private ExternalNewUserService ppmsNewUserService;

    /** @see TestKeys#LDAP_USERNAME */
    private String ldapUserName;

    /** @see TestKeys#LDAP_PWD_OK */
    private String ldapRightPassword;

    /** @see TestKeys#LDAP_PWD_KO */
    private String ldapWrongPassword;

    @Before
    public void setUp() {
        // spring beans
        ppmsNewUserService = (ExternalNewUserService) omeroContext.getBean("ppmsNewUserService");

        // config settings
        ldapUserName = configProperties.getProperty(TestKeys.LDAP_USERNAME);
        ldapRightPassword = configProperties.getProperty(TestKeys.LDAP_PWD_OK);
        ldapWrongPassword = configProperties.getProperty(TestKeys.LDAP_PWD_KO);
    }

    @Test
    @PerfTest(invocations = BenchUtil.ACCOUNT_LOCKING_SAFE_ITERATIONS,
              timer = ConstantTimer.class, timerParams = { BenchUtil.WAIT_DEFAULT })
    @Required(max = 500, median = 500, percentile90 = 500, percentile95 = 500)
    public void validatePasswordLdapAuth() {
        boolean success = ppmsNewUserService.validatePassword(ldapUserName, ldapRightPassword);
        assertTrue("should auth ok", success);
    }

    @Test
    @PerfTest(invocations = BenchUtil.ACCOUNT_LOCKING_SAFE_ITERATIONS,
              timer = ConstantTimer.class, timerParams = { BenchUtil.WAIT_DEFAULT })
    @Required(max = 500, median = 500, percentile90 = 500, percentile95 = 500)
    public void validatePasswordLdapNoAuth() {
        boolean success = ppmsNewUserService.validatePassword(ldapUserName, ldapWrongPassword);
        assertFalse("should auth ko", success);
    }

}
