/**
 *
 */
package org.imagopole.omero.auth.api;

/**
 * Runtime exception for error conditions originating from remote service invocations.
 *
 * Allows for exception translation of the underlying service implementation-specific exceptions
 * into a common denominator.
 *
 * @author seb
 *
 */
public class ExternalServiceException extends RuntimeException {

    /**
     * serialVersionUID
     */
    private static final long serialVersionUID = 1L;

    /**
     * Vanilla constructor.
     */
    public ExternalServiceException() {
        super();
    }

    /**
     * Parameterized constructor.
     *
     * @param message exception message
     */
    public ExternalServiceException(String message) {
        super(message);
    }

    /**
     * Parameterized constructor.
     *
     * @param cause root cause
     */
    public ExternalServiceException(Throwable cause) {
        super(cause);
    }

    /**
     * Parameterized constructor.
     *
     * @param message exception message
     * @param cause root cause
     */
    public ExternalServiceException(String message, Throwable cause) {
        super(message, cause);
    }

}
