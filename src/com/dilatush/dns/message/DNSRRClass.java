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
 * Enumerates the possible resource classes, and defines their codes and text representations.
 *
 * @author Tom Dilatush  tom@dilatush.com
 */
@SuppressWarnings( "unused" )
public enum DNSRRClass {

    IN  ( false, "IN", 1   ),    // A request for a transfer of an entire zone...
    CS  ( false, "CS", 2   ),    // A request for mailbox-related records (MB, MG or MR)...
    CH  ( false, "CH", 3   ),    // A request for mail agent RRs (Obsolete - see MX)...
    HS  ( false, "HS", 4   ),    // A request for all records...
    ANY ( true,  "*",  255 );    // A request for all classes...


    private static final Outcome.Forge<DNSRRClass> outcome       = new Outcome.Forge<>();
    private static final Outcome.Forge<?>          encodeOutcome = new Outcome.Forge<>();

    /** {@code true} if this class is only valid in a query. */
    public final boolean isQCLASS;

    /** The textual representation of this class. */
    public final String  text;

    /** The value (code) of this class in a resource record. */
    public final int     code;

    /** The number of bytes that encode this class in a resource record. */
    public final int     length;


    // map of text representation to enum instance...
    private static final Map<String, DNSRRClass>   fromText = new HashMap<>();  // mapping of text representation to instances of this class...

    // map of code to enum instance, for decoding...
    private static final Map<Integer, DNSRRClass>  fromCode = new HashMap<>();  // mapping of values (codes) to instances of this class...

    // the maps above are initialized statically here because we can't do it from the constructor...
    // see this good explanation:  https://stackoverflow.com/questions/443980/why-cant-enums-constructor-access-static-fields
    static {
        for( DNSRRClass t : DNSRRClass.values() ) {
            fromText.put( t.text, t );
            fromCode.put( t.code, t );
        }
    }


    /**
     * Creates a new instance of this enum with the given arguments.
     *
     * @param _isQCLASS {@code true} if this instance can only be used in a query.
     * @param _text The text representation of this class.
     * @param _code The code value for this class.
     */
    DNSRRClass( final boolean _isQCLASS, final String _text, final int _code ) {

        isQCLASS = _isQCLASS;
        text = _text;
        code = _code;
        length = 2;  // always encoded as 16 bits...
    }


    /**
     * Return the bytes that encode this class in a resource record.
     *
     * @return the bytes that encode this class in a resource record.
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
     * Returns the {@link DNSRRClass} instance with the given value (code), or {@code null} if there are none.
     *
     * @param _code The value (code) for the desired {@link DNSRRClass}.
     * @return the {@link DNSRRClass} with the given value (code), or {@code null} if there are none.
     */
    public static DNSRRClass fromCode( final int _code ) {
        return fromCode.get( _code );
    }


    /**
     * Returns the {@link DNSRRClass} instance with the given text representation, or {@code null} if there are none.
     *
     * @param _text The text representation for the desired {@link DNSRRClass}.
     * @return the {@link DNSRRClass} with the given value (code), or {@code null} if there are none.
     */
    public static DNSRRClass fromText( final String _text ) {
        return fromText.get( _text );
    }


    /**
     * Attempts to create an instance of {@link DNSRRClass} from the given buffer, using bytes at the buffer's current position.  If the attempt is
     * successful, then the returned outcome is ok and the newly created instance of {@link DNSRRClass} is the information in the outcome.  If the
     * attempt fails, then the outcome is not ok and the message explains why.
     *
     * @param _buffer The {@link ByteBuffer} containing the bytes encoding the label.
     * @return The {@link Outcome Outcome&lt;DNSRRClass&gt;} giving the results of the attempt.
     */
    public static Outcome<DNSRRClass> decode( final ByteBuffer _buffer ) {

        Checks.required( _buffer );

        if( _buffer.remaining() < 2 )
            return outcome.notOk( "Decoder buffer underflow", new DNSResolverException( "Buffer underflow", DNSResolverError.DECODER_BUFFER_UNDERFLOW ) );

        // extract the 16 bit code (value)...
        int code = 0xffff & _buffer.getShort();

        // try to decode it...
        DNSRRClass result = fromCode( code );

        if( isNull( result ) )
            return outcome.notOk(
                    "Could not decode resource record class code: " + code,
                    new DNSResolverException( "Invalid class code", DNSResolverError.INVALID_RESOURCE_RECORD_CLASS_CODE )
            );

        return outcome.ok( result );
    }
}
