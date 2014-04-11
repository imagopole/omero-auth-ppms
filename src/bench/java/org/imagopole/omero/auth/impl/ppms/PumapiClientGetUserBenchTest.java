/**
 *
 */
package org.imagopole.omero.auth.impl.ppms;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;

import org.databene.contiperf.PerfTest;
import org.databene.contiperf.Required;
import org.databene.contiperf.timer.ConstantTimer;
import org.imagopole.omero.auth.BenchUtil;
import org.imagopole.ppms.api.dto.PpmsUser;
import org.junit.Test;

/**
 * @author seb
 *
 */
@PerfTest(invocations = BenchUtil.ITERATIONS_DEFAULT,
          timer = ConstantTimer.class,
          timerParams = { BenchUtil.WAIT_DEFAULT })
public class PumapiClientGetUserBenchTest extends AbstractPumapiClientBenchTest {

    @Test
    @Required(max = 100, median = 100, percentile90 = 100, percentile95 = 100)
    public void ldapFoundNoCache() {
        PpmsUser user = defaultClient.getUser(ldapUserName);
        assertNotNull("should exist", user);
    }

    @Test
    @Required(max = 100, median = 100, percentile90 = 100, percentile95 = 100)
    public void ldapFoundCache() {
        PpmsUser user = cachingClient.getUser(ldapUserName);
        assertNotNull("should exist", user);
    }

    @Test
    @Required(max = 100, median = 100, percentile90 = 100, percentile95 = 100)
    public void localFoundNoCache() {
        PpmsUser user = defaultClient.getUser(localUsername);
        assertNotNull("should exist", user);
    }

    @Test
    @Required(max = 100, median = 100, percentile90 = 100, percentile95 = 100)
    public void localFoundCache() {
        PpmsUser user = cachingClient.getUser(localUsername);
        assertNotNull("should exist", user);
    }

    @Test
    @Required(max = 100, median = 100, percentile90 = 100, percentile95 = 100)
    public void notFoundNoCache() {
        PpmsUser user = defaultClient.getUser(unknownUsername);
        assertNull("should not exist", user);
    }

    @Test
    @Required(max = 100, median = 100, percentile90 = 100, percentile95 = 100)
    public void notFoundCache() {
        PpmsUser user = cachingClient.getUser(unknownUsername);
        assertNull("should not exist", user);
    }

}
