/**
 *
 */
package org.imagopole.omero.auth.api.ppms;

import org.imagopole.ppms.api.dto.PpmsGroup;
import org.imagopole.ppms.api.dto.PpmsUser;
import org.imagopole.ppms.util.Check;

/**
 * Aggregate information for a PPMS user and its affiliation (retrieved via the PPMS group information).
 *
 * @author seb
 *
 */
public class PpmsUserDetails {

    /** Basic user information. */
    private PpmsUser user;

    /** Extended user information. */
    private PpmsGroup group;

    public PpmsUserDetails(PpmsUser user) {
        super();
        Check.notNull(user, "user");

        this.user = user;
    }

    public PpmsUserDetails(PpmsUser user, PpmsGroup group) {
        super();
        Check.notNull(user, "user");
        Check.notNull(group, "group");

        this.user = user;
        this.group = group;
    }

    public boolean isExternalAffiliation() {
        boolean result = false;

        if (null != getGroup()) {

            Boolean isExternalGroup = getGroup().getExt();
            result = (null != isExternalGroup && isExternalGroup);

        }

        return result;
    }

    /**
     * Returns user.
     * @return the user
     */
    public PpmsUser getUser() {
        return user;
    }

    /**
     * Sets user.
     * @param user the user to set
     */
    public void setUser(PpmsUser user) {
        this.user = user;
    }

    /**
     * Returns group.
     * @return the group
     */
    public PpmsGroup getGroup() {
        return group;
    }

    /**
     * Sets group.
     * @param group the group to set
     */
    public void setGroup(PpmsGroup group) {
        this.group = group;
    }

}
