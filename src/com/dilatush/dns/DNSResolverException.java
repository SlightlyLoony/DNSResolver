package com.dilatush.dns;

public class DNSResolverException extends DNSException {


    public final DNSResolverError error;

    public DNSResolverException( final String message, final DNSResolverError _error ) {
        super( message );
        error = _error;
    }


    public DNSResolverException( final String message, final Throwable cause, final DNSResolverError _error ) {
        super( message, cause );
        error = _error;
    }
}
