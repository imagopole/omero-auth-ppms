/**
 *
 */
package org.imagopole.omero.auth.impl.ppms;


import java.util.ArrayList;
import java.util.List;

import ome.model.meta.Experimenter;

import org.imagopole.omero.auth.api.ExternalAuthConfig;
import org.imagopole.omero.auth.api.dto.NamedItem;
import org.imagopole.omero.auth.util.ConvertUtil;
import org.imagopole.ppms.api.dto.PpmsSystem;
import org.imagopole.ppms.api.dto.PpmsUser;
import org.imagopole.ppms.util.Check;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * @author seb
 *
 */
public final class PpmsUtil {

    /** Application logs. */
    private static final Logger LOG = LoggerFactory.getLogger(PpmsUtil.class);

    /**
     * Util.
     */
    private PpmsUtil() {
        super();
    }

    public static final List<PpmsSystem> filterSystemsByFacilityAndType(
                    List<PpmsSystem> systems,
                    ExternalAuthConfig config) {
        Check.notNull(config, "config");

        List<PpmsSystem> result = new ArrayList<PpmsSystem>();

        if (null != systems && !systems.isEmpty()) {

            List<Long> includeFacilities = listIncludedFacilities(config);
            List<String> includeTypes = listIncludedSystemTypes(config);

            LOG.debug("[external_auth][ppms] filtering PPMS systems for facilities: {} and types: {}",
                      includeFacilities, includeTypes);

            for (PpmsSystem system : systems) {
                Long systemFacility = system.getCoreFacilityRef();
                String systemType = system.getType();

                boolean isFacilityIncluded = includeFacilities.contains(systemFacility);
                boolean isSystemTypeIncluded = includeTypes.contains(systemType);
                boolean includeSystem = isFacilityIncluded && isSystemTypeIncluded;

                if (includeSystem) {
                    result.add(system);
                } else {
                    LOG.debug(
                        "[external_auth][ppms] skipping PPMS system: {}-{} [{}] of facility: {} and type: {} [{}:{}]",
                        system.getSystemId(), system.getName(), system.getActive(), systemFacility,
                        systemType, isFacilityIncluded, isSystemTypeIncluded);
                }
            }

        }

        return result;
    }

    public static final List<Long> listIncludedFacilities(ExternalAuthConfig config) {
        Check.notNull(config, "config");

        List<Long> result = new ArrayList<Long>();

        List<String> facilitiesWhitelist =
            ConvertUtil.lookupCsvValue(config, PpmsExternalConfigKeys.INCLUDE_FACILITIES);

        if (null != facilitiesWhitelist && !facilitiesWhitelist.isEmpty()) {

            for (String facilityRef : facilitiesWhitelist) {
                Long facilityId = ConvertUtil.parseLongOrNull(facilityRef);

                if (null != facilityId) {
                    result.add(facilityId);
                }
            }

        }

        return result;
    }

    public static final List<String> listIncludedSystemTypes(ExternalAuthConfig config) {
        Check.notNull(config, "config");
        return ConvertUtil.lookupCsvValue(config, PpmsExternalConfigKeys.INCLUDE_TYPES);
    }

    public static final List<NamedItem> toNamedItems(List<PpmsSystem> systems) {
        List<NamedItem> result = new ArrayList<NamedItem>();

        if (null != systems && !systems.isEmpty()) {

            for (PpmsSystem system : systems) {
                result.add(toNamedItem(system));
            }

        }

        return result;
    }

    public static final NamedItem toNamedItem(PpmsSystem system) {
        Check.notNull(system, "system");

        String systemId = ConvertUtil.toStringOrBlank(system.getSystemId());
        String systemName = system.getName();
        String systemDesc = String.format("%s [%s]", system.getType(), system.getLocalisation());

        NamedItem result = NamedItem.newItem(systemId, systemName, systemDesc);

        return result;
    }

    public static final Experimenter toExperimenter(PpmsUser ppmsUser) {
        Check.notNull(ppmsUser, "ppmsUser");

        Experimenter person = new Experimenter();

        person.setOmeName(ppmsUser.getLogin());
        person.setFirstName(ppmsUser.getFname());
        person.setLastName(ppmsUser.getLname());
        // person.setInstitution(null);
        person.setEmail(ppmsUser.getEmail());
        person.setLdap(Boolean.FALSE); // @since omero 5.1.0 (non-null 'ldap' boolean replaces 'dn' string)

        // note: could be interesting to define some extra external info here
        // ExternalInfo ppmsInfo = new ExternalInfo();
        // ppmsInfo.setEntityType("/ppms/user"); // or Experimenter.class.getName(), or configurable token
        // ppmsInfo.setEntityId(ppmsUser.getPpmsId());
        // person.getDetails().setExternalInfo(ppmsInfo);

        return person;
    }

    /**
     * Keys for configuration settings defined in the application context.
     *
     * @see org.imagopole.omero.auth.impl.DefaultExternalAuthConfig
     * @see org.imagopole.omero.auth.impl.group.ConfigurableNameToGroupBean
     * @see org.imagopole.omero.auth.impl.ExternalConfigurablePasswordProvider
     */
    private class PpmsExternalConfigKeys {

        /** Common namespace for all settings related to ppms. */
        private static final String PREFIX             = "omero.ppms.";

        private static final String INCLUDE_FACILITIES = PREFIX + "systems.include_facilities";

        private static final String INCLUDE_TYPES      = PREFIX + "systems.include_types";

        /** Constants class. */
        private PpmsExternalConfigKeys() {
            super();
        }
    }

}
