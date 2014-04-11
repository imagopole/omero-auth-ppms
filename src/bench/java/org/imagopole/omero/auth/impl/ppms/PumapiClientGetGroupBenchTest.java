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
import org.imagopole.ppms.api.dto.PpmsGroup;
import org.junit.Test;

/**
 * @author seb
 *
 */
@PerfTest(invocations = BenchUtil.ITERATIONS_DEFAULT,
          timer = ConstantTimer.class,
          timerParams = { BenchUtil.WAIT_DEFAULT })
public class PumapiClientGetGroupBenchTest extends AbstractPumapiClientBenchTest {

    @Test
    @Required(max = 100, median = 100, percentile90 = 100, percentile95 = 100)
    public void foundNoCache() {
        PpmsGroup group = defaultClient.getGroup(groupKey);
        assertNotNull("should exist", group);
    }

    @Test
    @Required(max = 100, median = 100, percentile90 = 100, percentile95 = 100)
    public void foundCache() {
        PpmsGroup group = cachingClient.getGroup(groupKey);
        assertNotNull("should exist", group);
    }

    @Test
    @Required(max = 100, median = 100, percentile90 = 100, percentile95 = 100)
    public void notFoundNoCache() {
        PpmsGroup group = defaultClient.getGroup(unknownGroupKey);
        assertNull("should not exist", group);
    }

    @Test
    @Required(max = 100, median = 100, percentile90 = 100, percentile95 = 100)
    public void notFoundCache() {
        PpmsGroup group = cachingClient.getGroup(unknownGroupKey);
        assertNull("should not exist", group);
    }

}
