/**
 *
 */
package org.imagopole.omero.auth.api.dto;

import org.imagopole.ppms.util.Check;

/**
 * Simple attributes holder for group informations.
 *
 * @author seb
 *
 */
public class NamedItem {

    /** Group identifier token. May be a non-numeric value. */
    private String identifier;

    /** Group name. */
    private String name;

    /** Group description. */
    private String description;

    protected NamedItem(String identifier, String name, String description) {
        super();
        this.identifier = identifier;
        this.name = name;
        this.description = description;
    }

    public static NamedItem newItem(String identifier, String name, String description) {
        Check.notNull(identifier, "identifier");
        Check.notEmpty(name, "name");

        return new NamedItem(identifier, name, description);
    }

    public static NamedItem newItem(String name) {
        Check.notEmpty(name, "name");

        return new NamedItem(null, name, null);
    }

    /**
     * Returns identifier.
     * @return the identifier
     */
    public String getIdentifier() {
        return identifier;
    }

    /**
     * Sets identifier.
     * @param identifier the identifier to set
     */
    public void setIdentifier(String identifier) {
        this.identifier = identifier;
    }

    /**
     * Returns name.
     * @return the name
     */
    public String getName() {
        return name;
    }

    /**
     * Sets name.
     * @param name the name to set
     */
    public void setName(String name) {
        this.name = name;
    }

    /**
     * Returns description.
     * @return the description
     */
    public String getDescription() {
        return description;
    }

    /**
     * Sets description.
     * @param description the description to set
     */
    public void setDescription(String description) {
        this.description = description;
    }

}
