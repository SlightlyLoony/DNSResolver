package com.dilatush.dns.message;

import java.util.HashMap;
import java.util.Map;

/**
 * Enumerates all the possible DNS message op codes.
 *
 * @author Tom Dilatush  tom@dilatush.com
 */
@SuppressWarnings( "unused" )
public enum DNSOpCode {

    QUERY ( 0 ),  // a standard query...
    IQUERY( 1 ),  // an inverse query...
    STATUS( 2 ),  // a status request...
    NOTIFY( 4 ),  // a notification of zone change...
    UPDATE( 5 );  // a dynamic DNS update...

    // remaining possible values (codes) 3, 6-15 are reserved for future use...

    // map of the code to the enum value (for decoding)...
    // initialized statically because we can't do it from the constructor...
    // see this good explanation:  https://stackoverflow.com/questions/443980/why-cant-enums-constructor-access-static-fields
    private static final Map<Integer, DNSOpCode> fromCode = new HashMap<>();
    static {
        for( DNSOpCode t : DNSOpCode.values() ) {
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
    DNSOpCode( final int _code ) {
        code = _code;
    }


    /**
     * Returns the {@link DNSOpCode} instance with the given value (code), or {@code null} if there are none.
     *
     * @param _code The value (code) for the desired {@link DNSOpCode}.
     * @return the {@link DNSOpCode} with the given value (code), or {@code null} if there are none.
     */
    public static DNSOpCode fromCode( final int _code ) {
        return fromCode.get( _code );
    }
}
