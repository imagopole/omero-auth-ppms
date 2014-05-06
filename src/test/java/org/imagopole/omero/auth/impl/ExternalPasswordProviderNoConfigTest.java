package org.imagopole.omero.auth.impl;

import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertNull;

import java.util.Properties;

import ome.system.OmeroContext;

import org.imagopole.omero.auth.AbstractOmeroServerTest;
import org.imagopole.omero.auth.TestsUtil.Env;
import org.imagopole.omero.auth.TestsUtil.PpmsUnit;
import org.testng.annotations.Test;

public class ExternalPasswordProviderNoConfigTest extends AbstractOmeroServerTest {

    /** @TestedObject */
    private ExternalConfigurablePasswordProvider passwordProvider;

    @Override
    protected void setUpBeforeServerStartup(Properties systemProps) {
        // disable the external PPMS service
        systemProps.remove(Env.PPMS_CONFIG);
    }

    @Override
    protected void setUpAfterServerStartup(OmeroContext omeroContext) {
        this.passwordProvider = (ExternalConfigurablePasswordProvider) omeroContext.getBean("ppmsPasswordProvider");
    }

    @Test
    public void hasUsernameShouldReturnNullWhenServiceIsDisabled() {
        Boolean result = passwordProvider.hasUsername(PpmsUnit.OMERO_USER);

        assertNull(result, "Null result expected");
    }

    @Test
    public void checkPasswordShouldReturnNullWhenServiceIsDisabled() {
        Boolean result = passwordProvider.checkPassword(PpmsUnit.OMERO_USER, PpmsUnit.OMERO_PWD, true);

        assertNull(result, "Null result expected");
    }

    @Test
    public void hasPasswordShouldReturnFalseWhenServiceIsDisabled() {
        // TODO: ideally we would need to check that the user is present both in PPMS and OMERO
        // as a precondition (ie. have an active root session on the server, get hold of iAdmin
        // or iQuery, start an executor job with a read-only tx context to lookup the experimenter...)
        boolean result = passwordProvider.hasPassword(PpmsUnit.OMERO_USER);

        assertFalse(result, "False result expected");
    }

}
