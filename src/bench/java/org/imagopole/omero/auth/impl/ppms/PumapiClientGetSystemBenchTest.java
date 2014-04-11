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
import org.imagopole.ppms.api.dto.PpmsSystem;
import org.junit.Test;

/**
 * @author seb
 *
 */
@PerfTest(invocations = BenchUtil.ITERATIONS_DEFAULT,
          timer = ConstantTimer.class,
          timerParams = { BenchUtil.WAIT_DEFAULT })
public class PumapiClientGetSystemBenchTest extends AbstractPumapiClientBenchTest {

    @Test
    @Required(max = 100, median = 100, percentile90 = 100, percentile95 = 100)
    public void foundNoCache() {
        PpmsSystem system = defaultClient.getSystem(systemId);
        assertNotNull("should exist", system);
    }

    @Test
    @Required(max = 100, median = 100, percentile90 = 100, percentile95 = 100)
    public void foundCache() {
        PpmsSystem system = cachingClient.getSystem(systemId);
        assertNotNull("should exist", system);
    }

    @Test
    @Required(max = 100, median = 100, percentile90 = 100, percentile95 = 100)
    public void notFoundNoCache() {
        PpmsSystem system = defaultClient.getSystem(unknownSystemId);
        assertNull("should not exist", system);
    }

    @Test
    @Required(max = 100, median = 100, percentile90 = 100, percentile95 = 100)
    public void notFoundCache() {
        PpmsSystem system = cachingClient.getSystem(unknownSystemId);
        assertNull("should not exist", system);
    }

}
