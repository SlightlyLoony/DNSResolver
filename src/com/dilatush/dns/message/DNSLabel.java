package com.dilatush.dns.message;

import com.dilatush.dns.misc.DNSResolverError;
import com.dilatush.dns.misc.DNSResolverException;
import com.dilatush.util.Checks;
import com.dilatush.util.Outcome;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;

import static com.dilatush.util.Strings.isEmpty;

/**
 * Instances of this class represent DNS "labels", which are sequences of [0..63] ASCII characters.  A label may use the characters [a..z], [A..Z],
 * [0..9], plus a hyphen ('-'), but the first and last characters must not be a hyphen.  Instances of this class are immutable and threadsafe.
 *
 * @author Tom Dilatush  tom@dilatush.com
 */
public class DNSLabel {

    private static final Outcome.Forge<DNSLabel> outcome = new Outcome.Forge<>();

    /** The value of this label as a Java string. */
    public final String text;

    /** The number of bytes in the bytes representation of this label. */
    public final int    length;


    /**
     * Creates a new instance of this class from the given text.  Note that this constructor is private, and is called only from static factory
     * methods; it assumes that the parameter is valid.
     *
     * @param _text The text to create a new label from.
     */
    private DNSLabel( final String _text ) {
        text = _text.toLowerCase();
        length = text.length() + 1;
    }


    /**
     * Return the value of this label as a sequence of ASCII bytes prefixed by a length byte.
     *
     * @return the value of this label as a sequence of ASCII bytes prefixed by a length byte.
     */
    public byte[] bytes() {
        byte[] bytes = new byte[ 1 + text.length() ];  // leave room for the length byte...
        bytes[0] = (byte)text.length();
        System.arraycopy(
                text.getBytes( StandardCharsets.US_ASCII ), 0,   // get the text as ASCII bytes...
                bytes, 1, text.length()                         // stuff it away
        );
        return bytes;
    }


    /**
     * Attempts to create an instance of {@link DNSLabel} from the given text.  If the attempt is successful, then the returned outcome is ok
     * and the newly created instance of {@link DNSLabel} is the information in the outcome.  If the attempt fails, then the outcome is not ok
     * and the message explains why.
     *
     * @param _text The text to create a label from.
     * @return The {@link Outcome Outcome&lt;DNSLabel&gt;} giving the results of the attempt.
     */
    public static Outcome<DNSLabel> fromString( final String _text ) {

        // empty strings are not allowed...
        if( isEmpty( _text ) )
            return outcome.notOk(
                    "Cannot create an empty DNS label",
                    new DNSResolverException( "Empty label", DNSResolverError.INVALID_DOMAIN_NAME )
            );

        // strings with more than 63 characters are not allowed...
        if( _text.length() > 63 )
            return outcome.notOk(
                    "Cannot have more than 63 characters in a label: " + _text,
                    new DNSResolverException( "Label over 63 characters long", DNSResolverError.INVALID_DOMAIN_NAME )
            );

        // first we make sure that neither the first nor the last character is a hyphen...
        if( (_text.charAt( 0 ) == '-') || (_text.charAt( _text.length() - 1 ) == '-') )
            return outcome.notOk(
                    "Hyphens may not be either the first or last character in a label: " + _text,
                    new DNSResolverException( "Leading or trailing hyphen", DNSResolverError.INVALID_DOMAIN_NAME )
            );

        // to lower case for case insensitivity, then iterate over all the characters, checking them...
        for( char c : _text.toLowerCase().toCharArray() ) {
            if( !(
                    ((c >= 'a') && (c <= 'z')) ||
                    ((c >= 'A') && (c <= 'Z')) ||
                    ((c >= '0') && (c <= '9')) ||
                     (c == '-')
            ))
                return outcome.notOk( "Illegal character in label: " + _text, new DNSResolverException( "Illegal character", DNSResolverError.INVALID_DOMAIN_NAME ) );
        }

        // if we make it here, then the given text is fine, and we can make a label...
        return outcome.ok( new DNSLabel( _text ) );
    }


    /**
     * Attempts to create an instance of {@link DNSLabel} from the given buffer, using bytes at the buffer's current position.  If the attempt is
     * successful, then the returned outcome is ok and the newly created instance of {@link DNSLabel} is the information in the outcome.  If the
     * attempt fails, then the outcome is not ok and the message explains why.  Note this method will accept any text in the label; the assumption is that if it's
     * supplied by a DNS server (which is why we're decoding it), then it must be ok. The author has observed cases in the wild where periods were included inside the label;
     * if he saw this one, there are most likely many others.
     *
     * @param _buffer The {@link ByteBuffer} containing the bytes encoding the label.
     * @return The {@link Outcome Outcome&lt;DNSLabel&gt;} giving the results of the attempt.
     */
    public static Outcome<DNSLabel> decode( final ByteBuffer _buffer ) {

        Checks.required( _buffer);

        if( !_buffer.hasRemaining() )
            return outcome.notOk( "Decoder buffer underflow", new DNSResolverException( "Buffer underflow", DNSResolverError.DECODER_BUFFER_UNDERFLOW ) );

        // get the number of bytes (which is also the number of characters) in the label...
        int length = _buffer.get() & 0xFF;

        if( length > _buffer.remaining() )
            return outcome.notOk( "Decoder buffer underflow", new DNSResolverException( "Buffer underflow", DNSResolverError.DECODER_BUFFER_UNDERFLOW ) );

        byte[] b = new byte[length];
        _buffer.get( b );
        String text = new String( b, StandardCharsets.US_ASCII ).toLowerCase();

        return outcome.ok( new DNSLabel( text ) );
    }
}
