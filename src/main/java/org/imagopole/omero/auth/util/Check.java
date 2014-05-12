/**
 *
 */
package org.imagopole.omero.auth.util;




import java.util.Collection;
import java.util.Map;


/**
 * Utility class for input handling and validation.
 *
 * @author seb
 *
 */
public final class Check {

    /** Private constructor (utility class). */
    private Check() {
        super();
    }

    public static final void notNull(Object obj, String argName) {
        if (null == obj) {
             rejectEmptyParam(argName);
        }
    }

    public static final void notEmpty(String obj, String argName) {
        Check.notNull(obj, argName);

        if (obj.trim().isEmpty()) {
             rejectEmptyParam(argName);
        }
    }

    public static final void notEmpty(Collection<?> coll, String argName) {
        Check.notNull(coll, argName);

        if (coll.size() < 1) {
             rejectEmptyParam(argName);
        }
    }

    public static final void notEmpty(Map<?, ?> obj, String argName) {
        Check.notNull(obj, argName);

        if (obj.keySet().isEmpty()) {
             rejectEmptyParam(argName);
        }
    }

    private static void rejectEmptyParam(String argName) throws IllegalArgumentException {
        throw new IllegalArgumentException(
                "Condition not met - expected : non-empty parameter for " + argName);
    }

    public static final boolean empty(String input) {
        return (null == input || input.trim().isEmpty());
    }
}
