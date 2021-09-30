package com.dilatush.dns.misc;

import com.dilatush.dns.message.DNSResponseCode;
import com.dilatush.util.Outcome;

/**
 * Instances of this class are returned as the cause in a "not ok" {@link Outcome} that is not ok because the DNS server returned a response code other than "OK".
 */
public class DNSServerException extends DNSException {

    public final DNSResponseCode responseCode;


    public DNSServerException( final String message, final DNSResponseCode _responseCode ) {
        super( message );
        responseCode = _responseCode;
    }
}
