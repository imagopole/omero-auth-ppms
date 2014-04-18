package org.imagopole.omero.auth.impl;

import java.util.Properties;

import ome.system.OmeroContext;

import org.imagopole.omero.auth.AbstractOmeroServerTest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class StandalonePpmsPasswordProviderTest extends AbstractOmeroServerTest {

    /** Application logs */
    private final Logger log = LoggerFactory.getLogger(StandalonePpmsPasswordProviderTest.class);

    /** @TestedObject */
    private ExternalConfigurablePasswordProvider passwordProvider;

    @Override
    protected void setUpBeforeServerStartup(Properties systemProps) {
        // no custom settings required
    }

    @Override
    protected void setUpAfterServerStartup(OmeroContext omeroContext) {
        this.passwordProvider = (ExternalConfigurablePasswordProvider) omeroContext.getBean("ppmsPasswordProvider");
    }

    //@Test
    public void testHasPassword() {
       log.debug("TODO: integration test {}", passwordProvider);
    }

}
