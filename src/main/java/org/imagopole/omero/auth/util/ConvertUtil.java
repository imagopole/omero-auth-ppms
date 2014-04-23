/**
 *
 */
package org.imagopole.omero.auth.util;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import ome.model.internal.Permissions;
import ome.model.internal.Permissions.Right;
import ome.model.internal.Permissions.Role;

import org.imagopole.omero.auth.api.ExternalAuthConfig;
import org.imagopole.omero.auth.api.dto.NamedItem;
import org.imagopole.omero.auth.impl.DefaultExternalAuthConfig.ConfigValues;
import org.imagopole.ppms.util.Check;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Utility class for input conversion handling.
 *
 * @author seb
 *
 */
public final class ConvertUtil {

    /** Application logs */
    private static final Logger LOG = LoggerFactory.getLogger(ConvertUtil.class);

    /** CSV config separator. */
    private static final String COMMA = ",";

    /**
     * RWR_RA_ : all can read, user can write, group can annotate */
    protected static final Permissions PERMISSION_READ_ANNOTATE =
        new Permissions(Permissions.GROUP_READABLE).grant(Role.GROUP, Right.ANNOTATE);

    /**
     * Private util.
     */
    private ConvertUtil() {
        super();
    }

    public static final String toStringOrBlank(Long input) {
        String result = "";

        if (null != input) {

            result = input.toString();

        }

        return result;
    }

    public static final Long parseLongOrNull(String input) {
        Long result = null;

        if (null != input && !input.isEmpty()) {

            try {
                result = Long.parseLong(input);
            } catch (NumberFormatException ignore) {
                LOG.debug("Invalid long: {} - ignoring", input);
            }

        }

        return result;
    }

    public static final List<NamedItem> toSimpleNamedItems(List<String> names) {
        List<NamedItem> result = new ArrayList<NamedItem>();

        if (null != names && !names.isEmpty()) {

            for (String name : names) {
                result.add(NamedItem.newItem(name));
            }

        }

        return result;
    }

    public static final List<String> tokenizeCsv(String input) {
        List<String> result = new ArrayList<String>();

        if (null != input && !input.isEmpty()) {

            String[] tokens = input.trim().split(COMMA);
            if (null != tokens && tokens.length > 0) {

                for (String token : tokens) {
                    String sanitizedToken = token.trim();

                    if (!sanitizedToken.isEmpty()) {
                        result.add(sanitizedToken);
                    }

                }

            }

        }

        return result;
    }

    public static final List<String> lookupCsvValue(ExternalAuthConfig config, String key) {
        Check.notNull(config, "config");
        Check.notEmpty(key, "key");

        List<String> result = Collections.emptyList();

        Map<String, Object> configMap = config.getConfigMap();

        if (null != configMap && configMap.containsKey(key)) {
            String configCsv = (String) configMap.get(key);

            result = tokenizeCsv(configCsv);
        }

        return result;
    }

    public static Permissions toPermissionsOrNull(String permissionLevel) {
        Permissions result = null;

        if (null != permissionLevel && !permissionLevel.trim().isEmpty()) {

            if (ConfigValues.READ_ONLY.equals(permissionLevel)) {
                result = Permissions.GROUP_READABLE;
            } else if (ConfigValues.READ_ANNOTATE.equals(permissionLevel)) {
                result = ConvertUtil.PERMISSION_READ_ANNOTATE;
            } else {
                // default to private group
                result = Permissions.USER_PRIVATE;
            }

        }

        return result;
    }

}
