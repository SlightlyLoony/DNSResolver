package com.dilatush.dns.misc;

/**
 * Abstract base class for exceptions in the {@code com.dilatush.dns} package.
 */
public abstract class DNSException extends Exception {


    /**
     * Creates a new instance of this class with the given message.
     *
     * @param message The message for this exception.
     */
    public DNSException( final String message ) {
        super( message );
    }


    /**
     * Creates a new instance of this class with the given message and cause.
     *
     * @param message The message for this exception.
     * @param cause The cause of this exception.
     */
    public DNSException( final String message, final Throwable cause ) {
        super( message, cause );
    }
}
