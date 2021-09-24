package com.dilatush.dns;

public class DNSResolverException extends DNSException {


    public DNSResolverException( final String message ) {

        super( message );
    }


    public DNSResolverException( final String message, final Throwable cause ) {

        super( message, cause );
    }
}
