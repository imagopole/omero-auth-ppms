package org.imagopole.omero.auth.impl.ppms;

import static org.imagopole.omero.auth.TestsUtil.newPpmsUser;
import static org.testng.Assert.*;
import ome.model.meta.Experimenter;

import org.imagopole.ppms.api.dto.PpmsUser;
import org.testng.annotations.Test;
import org.unitils.UnitilsTestNG;

public class PpmsUtilTest extends UnitilsTestNG {

    @Test
    public void toExperimenterShouldSetLdapAttribute() {
        PpmsUser ppmsUnitUser = newPpmsUser();

        // the 5.1.0+ ldap attribute on Experimenter must be defined before being persisted
        // (non-nullable hibernate field - eg. see openmicroscopy/commit/edd3df97e5cfad1ec199fbf27c92245b5e3e6b80)
        Experimenter result = PpmsUtil.toExperimenter(ppmsUnitUser);

        assertNotNull(result, "Non null experimenter expected");
        assertNotNull(result.getLdap(), "Non null experimenter ldap attribute expected");
        assertEquals(result.getLdap().booleanValue(), false, "Wrong experimenter ldap attribute");
    }
}
