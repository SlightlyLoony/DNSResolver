package com.dilatush.dns.query;

import com.dilatush.dns.misc.DNSException;

public class DNSTimeoutException extends DNSException {


    public DNSTimeoutException( final String message ) {

        super( message );
    }


    public DNSTimeoutException( final String message, final Throwable cause ) {

        super( message, cause );
    }
}
