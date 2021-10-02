package com.dilatush.dns.misc;

import com.dilatush.dns.message.DNSResponseCode;
import com.dilatush.util.Outcome;

/**
 * Instances of this class are returned as the cause in a "not ok" {@link Outcome} that is not ok because the DNS server returned a response code other than "OK".
 */
public class DNSServerException extends DNSException {

    /** The {@link DNSResponseCode} with the response code returned by the DNS server. */
    public final DNSResponseCode responseCode;


    /**
     * Create a new instance of this class with the given message and response code.
     *
     * @param message The message describing the reason for this exception.
     * @param _responseCode The response code returned from the DNS server.
     */
    public DNSServerException( final String message, final DNSResponseCode _responseCode ) {
        super( message );
        responseCode = _responseCode;
    }
}
