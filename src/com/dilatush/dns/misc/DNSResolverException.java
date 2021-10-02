package com.dilatush.dns.misc;

import com.dilatush.util.Outcome;

/**
 * Instances of this class provide additional information about an error when provided as a cause in an {@link Outcome} instance.  Unlike most exceptions, these are not thrown.
 */
public class DNSResolverException extends DNSException {


    /** The {@link DNSResolverError} instance that best describes the reason for this exception.  */
    public final DNSResolverError error;


    /**
     * Create a new instance of this class with the given message and error.
     *
     * @param message The message for this instance.
     * @param _error The {@link DNSResolverError} for this instance.
     */
    public DNSResolverException( final String message, final DNSResolverError _error ) {
        super( message );
        error = _error;
    }


    /**
     * Create a new instance of this class with the given message, cause, and error.
     *
     * @param message The message for this instance.
     * @param cause The optional cause for this exception, used if the cause was another exception.
     * @param _error The {@link DNSResolverError} for this instance.
     */
    public DNSResolverException( final String message, final Throwable cause, final DNSResolverError _error ) {
        super( message, cause );
        error = _error;
    }
}
