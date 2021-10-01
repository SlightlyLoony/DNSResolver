package com.dilatush.dns.message;

import java.util.HashMap;
import java.util.Map;

/**
 * Enumerates all the possible DNS message response codes.
 *
 * @author Tom Dilatush  tom@dilatush.com
 */
@SuppressWarnings( "unused" )
public enum DNSResponseCode {

    OK              ( 0 ),  // No error condition...
    FORMAT_ERROR    ( 1 ),  // Unable to interpret query...
    SERVER_FAILURE  ( 2 ),  // Name server failure...
    NAME_ERROR      ( 3 ),  // Only from authoritative name servers - the queried domain name does not exist...
    NOT_IMPLEMENTED ( 4 ),  // Name server does not implement the kind of query...
    REFUSED         ( 5 );  // Name server refused to perform the operation (likely due to a policy)...

    // remaining possible values (codes) 6-15 are reserved for future use...

    // map of code to enum value, for decoding...
    // initialized statically because we can't do it from the constructor...
    // see this good explanation:  https://stackoverflow.com/questions/443980/why-cant-enums-constructor-access-static-fields
    private static final Map<Integer, DNSResponseCode> fromCode = new HashMap<>();
    static {
        for( DNSResponseCode t : DNSResponseCode.values() ) {
            fromCode.put( t.code, t );
        }
    }


    /** The value (code) of this op code in a DNS message. */
    public final int code;


    /**
     * Creates a new instance of this enum with the given code.
     *
     * @param _code The code value for this instance.
     */
    DNSResponseCode( final int _code ) {
        code = _code;
    }


    /**
     * Returns the {@link DNSResponseCode} instance with the given value (code), or {@code null} if there are none.
     *
     * @param _code The value (code) for the desired {@link DNSResponseCode}.
     * @return the {@link DNSResponseCode} with the given value (code), or {@code null} if there are none.
     */
    public static DNSResponseCode fromCode( final int _code ) {
        return fromCode.get( _code );
    }
}
