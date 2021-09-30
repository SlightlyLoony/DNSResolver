package com.dilatush.dns.misc;

public abstract class DNSException extends Exception {

    public DNSException( final String message ) {
        super( message );
    }

    public DNSException( final String message, final Throwable cause ) {
        super( message, cause );
    }
}
