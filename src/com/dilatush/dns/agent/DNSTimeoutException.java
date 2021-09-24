package com.dilatush.dns.agent;

import com.dilatush.dns.DNSException;

public class DNSTimeoutException extends DNSException {


    public DNSTimeoutException( final String message ) {

        super( message );
    }


    public DNSTimeoutException( final String message, final Throwable cause ) {

        super( message, cause );
    }
}
