/**
 *
 */
package org.imagopole.omero.auth.impl.ppms;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.util.List;

import org.databene.contiperf.PerfTest;
import org.databene.contiperf.Required;
import org.databene.contiperf.timer.ConstantTimer;
import org.imagopole.omero.auth.BenchUtil;
import org.imagopole.ppms.api.dto.PpmsUserPrivilege;
import org.junit.Test;

/**
 * @author seb
 *
 */
@PerfTest(invocations = BenchUtil.ITERATIONS_DEFAULT,
          timer = ConstantTimer.class,
          timerParams = { BenchUtil.WAIT_DEFAULT })
public class PumapiClientGetUserRightsBenchTest extends AbstractPumapiClientBenchTest {

    @Test
    @Required(max = 100, median = 100, percentile90 = 100, percentile95 = 100)
    public void ldapFoundNoCache() {
        List<PpmsUserPrivilege> privileges = defaultClient.getUserRights(ldapUserName);
        assertNotNull("should exist", privileges);
        assertFalse("should exist", privileges.isEmpty());
    }

    @Test
    @Required(max = 100, median = 100, percentile90 = 100, percentile95 = 100)
    public void ldapFoundCache() {
        List<PpmsUserPrivilege> privileges = cachingClient.getUserRights(ldapUserName);
        assertNotNull("should exist", privileges);
        assertFalse("should exist", privileges.isEmpty());
    }

    @Test
    @Required(max = 100, median = 100, percentile90 = 100, percentile95 = 100)
    public void localFoundNoCache() {
        List<PpmsUserPrivilege> privileges = defaultClient.getUserRights(localUsername);
        assertNotNull("should exist", privileges);
        assertFalse("should exist", privileges.isEmpty());
    }

    @Test
    @Required(max = 100, median = 100, percentile90 = 100, percentile95 = 100)
    public void localFoundCache() {
        List<PpmsUserPrivilege> privileges = cachingClient.getUserRights(localUsername);
        assertNotNull("should exist", privileges);
        assertFalse("should exist", privileges.isEmpty());
    }

    @Test
    @Required(max = 100, median = 100, percentile90 = 100, percentile95 = 100)
    public void notFoundNoCache() {
        List<PpmsUserPrivilege> privileges = defaultClient.getUserRights(unknownUsername);
        assertNotNull("should not be null", privileges);
        assertTrue("should not exist", privileges.isEmpty());
    }

    @Test
    @Required(max = 100, median = 100, percentile90 = 100, percentile95 = 100)
    public void notFoundCache() {
        List<PpmsUserPrivilege> privileges = cachingClient.getUserRights(unknownUsername);
        assertNotNull("should not be null", privileges);
        assertTrue("should not exist", privileges.isEmpty());
    }

}
