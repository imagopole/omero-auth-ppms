package org.imagopole.omero.auth;

import static org.testng.Assert.fail;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.Properties;

import ome.system.OmeroContext;

import org.imagopole.omero.auth.TestsUtil.Env;
import org.imagopole.omero.auth.util.Check;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Optional;
import org.testng.annotations.Parameters;
import org.unitils.UnitilsTestNG;

/**
 * Basic integration test with OMERO.server only.
 *
 * @author seb
 *
 */
public abstract class AbstractOmeroServerTest extends UnitilsTestNG {

    /** Application logs */
    private final Logger log = LoggerFactory.getLogger(AbstractOmeroServerTest.class);

    /** Client configuration settings. */
    private Properties configProperties;

    // @SpringBean("ome.server")
    private OmeroContext omeroContext;

    @BeforeClass
    @Parameters(Env.OMERO_CONFIG_LOCATION)
    public void setUpOmeroServer(@Optional String omeroConfigLocation) throws FileNotFoundException, IOException {

        String omeroConfig = System.getenv(Env.OMERO_CONFIG);

        Properties props = new Properties();
        if (!Check.empty(omeroConfig) && !Check.empty(omeroConfig.trim())) {
            log.debug("Loading OMERO.server configuration from 'OMERO_CONFIG' at {}", omeroConfig);

            props.load(new FileInputStream(omeroConfig));
        } else if (!Check.empty(omeroConfigLocation) && !Check.empty(omeroConfigLocation.trim())){
            log.debug("Loading OMERO.server  configuration from 'omero.config.location' at {}", omeroConfigLocation);

            props.load(new FileInputStream(omeroConfigLocation));
        } else {
            fail("Run integration tests with exported OMERO_CONFIG=/path/to/omero-local.properties "
                + "environment variable or -Domero.config.location=/path/to/omero-local.properties "
                + "JVM system property");
        }

        configureSystemProperties(props);

        configureIntegrationServer();
    }

    private void configureSystemProperties(Properties props) {
        Properties systemProperties = new Properties(System.getProperties());
        log.trace("Configuring OMERO.server from current system properties: {}", systemProperties);

        // merge omero config with current system props
        Properties overrideProperties = new Properties(systemProperties);
        overrideProperties.putAll(props);

        // subclasses config override hook
        setUpBeforeServerStartup(overrideProperties);

        log.trace("Configuring OMERO.server with config properties: {}", overrideProperties);
        this.configProperties = overrideProperties;
        System.setProperties(this.configProperties);
    }

    /**
     * Let subclasses override system properties/reconfigure server settings before startup.
     * @param customProps properties to be overridden
     */
    protected abstract void setUpBeforeServerStartup(Properties systemProps);

    /**
     * Let subclasses initialize from the OMERO spring application context.
     * @param omeroContext the loaded OMERO spring application context
     */
    protected abstract void setUpAfterServerStartup(OmeroContext omeroContext);

    private void configureIntegrationServer() {
        log.debug("Loading OMERO.server managed context");

        this.omeroContext = OmeroContext.getManagedServerContext();
        omeroContext.refreshAllIfNecessary();

        log.debug("Loaded OMERO.server managed context: {}", omeroContext);

        // subclasses initialization hook
        setUpAfterServerStartup(omeroContext);
    }

    @AfterClass
    public void tearDown() {
        if (null != omeroContext) {
            log.debug("Unloading OMERO.server managed context: {}", omeroContext);
            omeroContext.close();
        }
    }

}
