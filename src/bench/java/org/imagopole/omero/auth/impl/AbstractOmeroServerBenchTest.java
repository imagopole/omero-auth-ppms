package org.imagopole.omero.auth.impl;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.Properties;

import ome.system.OmeroContext;

import org.databene.contiperf.junit.ContiPerfRule;
import org.databene.contiperf.report.CSVSummaryReportModule;
import org.databene.contiperf.report.HtmlReportModule;
import org.imagopole.omero.auth.BenchUtil.Env;
import org.imagopole.omero.auth.util.Check;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static org.junit.Assert.fail;

/***
 *
 * @author seb
 *
 */
public class AbstractOmeroServerBenchTest {

    /** Application logs */
    private static final Logger LOG = LoggerFactory.getLogger(AbstractOmeroServerBenchTest.class);

    /** Bench configuration settings (read-only). */
    protected static Properties configProperties;

    /** OMERO.server managed spring context. */
    protected static OmeroContext omeroContext;

    @Rule
    public ContiPerfRule contiperfRule = new ContiPerfRule(new HtmlReportModule(),
                                                           new CSVSummaryReportModule());

    @BeforeClass
    public static void setUpOmeroServer() throws FileNotFoundException, IOException {

        String omeroConfig = System.getenv(Env.BENCH_CONFIG);
        String omeroConfigLocation = System.getProperty(Env.BENCH_CONFIG_LOCATION);

        Properties props = new Properties();
        if (!Check.empty(omeroConfig) && !Check.empty(omeroConfig.trim())) {
            LOG.debug("Loading OMERO.server configuration from 'BENCH_CONFIG' at {}", omeroConfig);

            props.load(new FileInputStream(omeroConfig));
        } else if (!Check.empty(omeroConfigLocation) && !Check.empty(omeroConfigLocation.trim())){
            LOG.debug("Loading OMERO.server configuration from 'bench.config.location' at {}", omeroConfigLocation);

            props.load(new FileInputStream(omeroConfigLocation));
        } else {
            fail("Run integration tests with exported BENCH_CONFIG=/path/to/bench-local.properties " +
                 "environment variable or -Dbench.config.location=/path/to/bench-local.properties " +
                 "JVM system property");
        }

        configureSystemProperties(props);
        configureIntegrationServer();
    }

    private static void configureSystemProperties(Properties props) {
        Properties mergedProperties = new Properties(System.getProperties());
        LOG.trace("Configuring OMERO.server from current system properties: {}", mergedProperties);

        mergedProperties.putAll(props);

        LOG.trace("Configuring OMERO.server with config properties: {}", mergedProperties);
        System.setProperties(mergedProperties);
        configProperties = mergedProperties;
    }

    private static void configureIntegrationServer() {
        LOG.debug("Loading OMERO.server managed context");

        omeroContext = OmeroContext.getManagedServerContext();
        omeroContext.refreshAllIfNecessary();

        LOG.debug("Loaded OMERO.server managed context: {}", omeroContext);
    }

    @AfterClass
    public static void tearDownOmeroServer() {
        if (null != omeroContext) {
            LOG.debug("Unloading OMERO.server managed context: {}", omeroContext);
            omeroContext.close();
        }
    }

}
