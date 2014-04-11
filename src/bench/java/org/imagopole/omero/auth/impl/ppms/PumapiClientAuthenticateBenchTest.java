/**
 *
 */
package org.imagopole.omero.auth.impl.ppms;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.databene.contiperf.PerfTest;
import org.databene.contiperf.Required;
import org.databene.contiperf.timer.ConstantTimer;
import org.imagopole.omero.auth.BenchUtil;
import org.junit.Ignore;
import org.junit.Test;

/**
 * @author seb
 *
 */
@PerfTest(invocations = BenchUtil.ACCOUNT_LOCKING_SAFE_ITERATIONS,
          timer = ConstantTimer.class,
          timerParams = { BenchUtil.WAIT_DEFAULT })
public class PumapiClientAuthenticateBenchTest extends AbstractPumapiClientBenchTest {

    @Test
    @Required(max = 500, median = 500, percentile90 = 500, percentile95 = 500)
    public void ldapFoundNoAuth() {
        boolean success = defaultClient.authenticate(ldapUserName, ldapWrongPassword);
        assertFalse("should auth ko", success);
    }

    @Test
    @Ignore
    @Required(max = 500, median = 500, percentile90 = 500, percentile95 = 500)
    public void ldapFoundAuth() {
        boolean success = defaultClient.authenticate(ldapUserName, ldapRightPassword);
        assertTrue("should auth ok", success);
    }

    @Test
    @Required(max = 500, median = 500, percentile90 = 500, percentile95 = 500)
    public void localFoundNoAuth() {
        boolean success = defaultClient.authenticate(localUsername, localWrongPassword);
        assertFalse("should auth ko", success);
    }

    @Test
    @Required(max = 500, median = 500, percentile90 = 500, percentile95 = 500)
    public void localFoundAuth() {
        boolean success = defaultClient.authenticate(localUsername, localRightPassword);
        assertTrue("should auth ok", success);
    }

    @Test
    @Required(max = 500, median = 500, percentile90 = 500, percentile95 = 500)
    public void notFound() {
        boolean success = defaultClient.authenticate(unknownUsername, "should-not-matter");
        assertFalse("should auth ko", success);
    }

}
