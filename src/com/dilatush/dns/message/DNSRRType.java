package com.dilatush.dns.message;

import com.dilatush.dns.misc.DNSResolverError;
import com.dilatush.dns.misc.DNSResolverException;
import com.dilatush.util.Checks;
import com.dilatush.util.Outcome;

import java.nio.BufferOverflowException;
import java.nio.ByteBuffer;
import java.util.HashMap;
import java.util.Map;

import static com.dilatush.util.General.isNull;

/**
 * Enumerates the possible resource record types (including QTYPES), and defines their codes and text representations.
 *
 * @author Tom Dilatush  tom@dilatush.com
 */
@SuppressWarnings( "unused" )
public enum DNSRRType {

    A     ( false, "A",     1   ),    // an IPv4 host address...
    NS    ( false, "NS",    2   ),    // an authoritative name server...
    CNAME ( false, "CNAME", 5   ),    // the canonical name for an alias...
    SOA   ( false, "SOA",   6   ),    // marks the start of a zone of authority...
    WKS   ( false, "WKS",   11  ),    // a well known service description...
    PTR   ( false, "PTR",   12  ),    // a domain name pointer...
    HINFO ( false, "HINFO", 13  ),    // host information...
    MINFO ( false, "MINFO", 14  ),    // mailbox or mail list information...
    MX    ( false, "MX",    15  ),    // mail exchange...
    TXT   ( false, "TXT",   16  ),    // text strings...
    AAAA  ( false, "AAAA",  28  ),    // an IPv6 host address...
    AXFR  ( true,  "AXFR",  252 ),    // A request for a transfer of an entire zone...
    MAILB ( true,  "MAILB", 253 ),    // A request for mailbox-related records (MB, MG or MR)...
    MAILA ( true,  "MAILA", 254 ),    // A request for mail agent RRs (Obsolete - see MX)...
    ANY   ( true,  "*",     255 ),    // A request for all records...
    UNIMPLEMENTED ( false, "UNIMPL", -1 );


    private static final Outcome.Forge<DNSRRType> outcome       = new Outcome.Forge<>();
    private static final Outcome.Forge<?>         encodeOutcome = new Outcome.Forge<>();

    /** {@code true} if this type is only valid in a query. */
    public final boolean isQTYPE;

    /** The textual representation of this type. */
    public final String  text;

    /** The value (code) of this type in a resource record. */
    public final int     code;

    /** The number of bytes that encode this type in a resource record. */
    public final int     length;


    // map of text representation to enum instance...
    private static final Map<String,DNSRRType>   fromText = new HashMap<>();  // mapping of text representation to instances of this class...

    // map of value (code) to enum instance, for decoding...
    private static final Map<Integer, DNSRRType> fromCode = new HashMap<>();  // mapping of values (codes) to instances of this class...

    // initialized statically because we can't do it from the constructor...
    // see this good explanation:  https://stackoverflow.com/questions/443980/why-cant-enums-constructor-access-static-fields
    static {
        for( DNSRRType t : DNSRRType.values() ) {
            fromText.put( t.text, t );
            fromCode.put( t.code, t );
        }
    }


    /**
     * Creates a new instance of this enum with the given arguments.
     *
     * @param _isQTYPE {@code true} if this instance can only be used in a query.
     * @param _text The text representation of this class.
     * @param _code The code value for this class.
     */
    DNSRRType( final boolean _isQTYPE, final String _text, final int _code ) {

        isQTYPE = _isQTYPE;
        text = _text;
        code = _code;
        length = 2;  // always encoded as 16 bits...
    }


    /**
     * Returns the bytes that encode this type in a resource record.
     *
     * @return the bytes that encode this type in a resource record.
     */
    public byte[] bytes() {
        byte[] bytes = new byte[2];
        bytes[0] = (byte)(code >>> 8);
        bytes[1] = (byte)(code);
        return bytes;
    }


    /**
     * Encodes this instance into the given {@link ByteBuffer} at its current position.  If the encoding was successful, an ok {@link Outcome} is
     * returned.  Otherwise, a not ok {@link Outcome} with an explanatory message is returned.  If the result was a buffer overflow, the outcome is
     * not ok with a cause of {@link BufferOverflowException}.
     *
     * @param _msgBuffer The {@link ByteBuffer} to encode this instance into.
     * @return the bytes that encode this question.
     */
    public Outcome<?> encode( final ByteBuffer _msgBuffer ) {

        Checks.required( _msgBuffer );

        if( _msgBuffer.remaining() < 2 )
            return outcome.notOk( "Encoder buffer overflow", new DNSResolverException( "Buffer overflow", DNSResolverError.ENCODER_BUFFER_OVERFLOW ) );

        _msgBuffer.putShort( (short) code );
        return encodeOutcome.ok();
    }


    /**
     * Returns the {@link DNSRRType} instance with the given value (code), or {@code null} if there are none.
     *
     * @param _code The value (code) for the desired {@link DNSRRType}.
     * @return the {@link DNSRRType} with the given value (code), or {@code null} if there are none.
     */
    public static DNSRRType fromCode( final int _code ) {
        return fromCode.get( _code );
    }


    /**
     * Returns the {@link DNSRRType} instance with the given text representation, or {@code null} if there are none.
     *
     * @param _text The text representation for the desired {@link DNSRRType}.
     * @return the {@link DNSRRType} with the given value (code), or {@code null} if there are none.
     */
    public static DNSRRType fromText( final String _text ) {
        return fromText.get( _text );
    }


    /**
     * Attempts to create an instance of {@link DNSRRType} from the given buffer, using bytes at the buffer's current position.  If the attempt is
     * successful, then the returned outcome is ok and the newly created instance of {@link DNSRRType} is the information in the outcome.  If the
     * attempt fails, then the outcome is still ok, but {@link #UNIMPLEMENTED}, so that resource record types this package is unaware of may still be
     * decoded.
     *
     * @param _buffer The {@link ByteBuffer} containing the bytes encoding the label.
     * @return The {@link Outcome Outcome&lt;DNSRRType&gt;} giving the results of the attempt.
     */
    public static Outcome<DNSRRType> decode( final ByteBuffer _buffer ) {

        Checks.required( _buffer );

        // make sure we have enough bytes left...
        if( _buffer.remaining() < 2 )
            return outcome.notOk( "Decoder buffer underflow", new DNSResolverException( "Buffer underflow", DNSResolverError.DECODER_BUFFER_UNDERFLOW ) );

        // extract the 16 bit code (value)...
        int code = 0xffff & _buffer.getShort();

        // try to decode it...
        DNSRRType result = fromCode( code );

        return isNull( result )
                ? outcome.ok( UNIMPLEMENTED )
                : outcome.ok( result );
    }
}
