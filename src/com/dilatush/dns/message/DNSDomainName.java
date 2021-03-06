package com.dilatush.dns.message;

import com.dilatush.dns.misc.DNSResolverError;
import com.dilatush.dns.misc.DNSResolverException;
import com.dilatush.util.Checks;
import com.dilatush.util.Outcome;

import java.nio.BufferOverflowException;
import java.nio.ByteBuffer;
import java.util.*;

/**
 * Instances of this class represent a DNS domain name, which is a sequence of DNS labels.  Instances of this class are immutable and threadsafe.
 *
 * @author Tom Dilatush  tom@dilatush.com
 */
@SuppressWarnings( "unused" )
public class DNSDomainName {

    private static final Outcome.Forge<DNSDomainName> outcome = new Outcome.Forge<>();

    /** This domain name as a Java string, in lower-case (for domain name case insensitivity).  */
    public final String         text;

    /** The length of the bytes representing this domain name. */
    public final int            length;

    /** This domain name as a sequence of {@link DNSLabel} instances. */
    public final List<DNSLabel> labels;


    /**
     * Creates a new instance of this class from the given sequence of {@link DNSLabel} instances.  Note that this constructor is private, and is
     * called only from static factory methods; it assumes that the parameter is valid.
     *
     * @param _labels The sequence of {@link DNSLabel} instances to create this domain name from.
     */
    private DNSDomainName( final List<DNSLabel> _labels ) {

        labels = Collections.unmodifiableList( _labels );  // make the list immutable, as "labels" is public final...

        // compute the encoded name's length...
        int len = 0;
        for( DNSLabel label : labels )
            len += label.length;
        length = len + 1;  // the +1 is for the null termination byte...

        // get the text representation...
        StringBuilder sb = new StringBuilder( length + labels.size() - 1 );
        for( DNSLabel label : labels ) {
            if( !sb.isEmpty() )
                sb.append( '.' );
            sb.append( label.text );
        }
        text = sb.toString().toLowerCase();
    }


    /**
     * Return this domain name as a sequence of labels encoded in bytes, with a byte containing zero as a suffix.  Note that this is done outside the context of a
     * particular message, so the result is not compressed.
     *
     * @return this domain name as a sequence of labels encoded in bytes, with a byte containing zero as a suffix.
     */
    public byte[] bytes() {

        // get the byte representation...
        byte[] bytes = new byte[length + 1];  // the +1 is for the null termination byte...
        int pos = 0;
        for( DNSLabel label : labels ) {
            System.arraycopy( label.bytes(), 0, bytes, pos, label.length );
            pos += label.length;
        }
        return bytes;
    }

    /*
     * DNS message compression is quite simple conceptually.  It operates only on domain names.  Consider a message where the same complete domain
     * name was used twice.  The first time, the entire domain name must be directly encoded.  The second time, however, all that's needed is a
     * pointer back to the first name:
     *    00: ...
     *    10: "a.b.c"
     *    20: ...
     *    30: (pointer to 10)
     * There are details not documented above, but that gives you the idea.  Now suppose we first used "a.b.c", and then "d.b.c".  In this case,
     * we have something slightly more complicated:
     *    00: ...
     *    10: abc
     *    20: ...
     *    30: d(pointer to 11)
     * The second domain name has to directly encode the "d", since we've never seen that before - but the "b.c" we HAVE seen before, and we can
     * just point to it instead of directly encoding it a second time.  It's possible to come up with more complicated scenarios, though I'm not sure
     * how likely they are in actual practice.  Consider a DNS message that encodes first "a.b.c", then "d.e.c", then "f.e.c".  This would get
     * encoded something like this:
     *    00: ...
     *    10: abc
     *    20: ...
     *    30: de(pointer to 12)
     *    40: ...
     *    50: f(pointer to 31)
     * When decoding that last case, we decode first the "f", then follow the pointer to "e", then follow the pointer to "c".
     */

    /**
     * Encode this domain name into the given DNS message {@link ByteBuffer} at the current buffer position, using message compression when possible.  The
     * given map of name offsets is indexed by string representations of domain names and sub-domain names that are already directly encoded in the
     * message.  If this domain name (or its sub-domain names) matches any of them, an offset is encoded instead of the actual characters.  Otherwise,
     * the name is directly encoded.  Any directly encoded domains or sub-domains is added to the map of offsets.  For example, the first time (in a
     * given message) that "www.cnn.com" is encoded, offsets are added for "www.cnn.com", "cnn.com", and "com".  The outcome returned is ok if the
     * encoding was successful, and not ok (with a message) if there was a problem.  If the result was a buffer overflow, the outcome is not ok with
     * a cause of {@link BufferOverflowException}.
     *
     * @param _msgBuffer The {@link ByteBuffer} to encode this instance into.
     * @param _nameOffsets The map of domain and sub-domain names that have been directly encoded, and their associated offset.
     * @return the {@link Outcome}, either ok or not ok with an explanatory message.
     */
    public Outcome<?> encode( final ByteBuffer _msgBuffer, final Map<String,Integer> _nameOffsets ) {

        Checks.required( _msgBuffer, _nameOffsets );

        // iterate over the complete domain name, and then its sub-domains...
        List<DNSLabel> ls = new ArrayList<>( labels );
        while( ls.size() > 0 ) {

            // we know this name is good, so the ".info()" never resolves to null...
            DNSDomainName dnsName = DNSDomainName.fromLabels( ls ).info();

            // if we have an offset for this domain or sub-domain, it's already been directly encoded, and we can compress it...
            Integer offset = _nameOffsets.get( dnsName.text );
            if( offset != null ) {

                // check that we have the space in our buffer...
                if( _msgBuffer.remaining() < 2 )
                    return outcome.notOk(
                            "Encoder buffer overflow",
                            new DNSResolverException( "Encoder buffer overflow", DNSResolverError.ENCODER_BUFFER_OVERFLOW )
                    );

                // create and encode the offset pointer, and we're done...
                // note that no terminating null is needed in this case...
                // the 0xC000 marks this as an offset, rather than a character; 0xC? is not a valid ASCII character...
                int ptr = 0xC000 + offset;
                _msgBuffer.putShort( (short) ptr );
                return outcome.ok();
            }

            // no offset, so this is the first time we've seen this -- directly encode this label...

            // check that we have the space in our buffer...
            if( ls.get( 0 ).length > _msgBuffer.remaining() )
                return outcome.notOk(
                        "Encoder buffer overflow",
                        new DNSResolverException( "Encoder buffer overflow", DNSResolverError.ENCODER_BUFFER_OVERFLOW )
                );

            // if the position is within the offset pointer range, map the offset to this domain or sub-domain, in case we ever see it again...
            if( (_msgBuffer.position() & 0xFFFFC000) == 0 )
                _nameOffsets.put( dnsName.text, _msgBuffer.position() );

            // encode this label into our message buffer...
            _msgBuffer.put( ls.get( 0 ).bytes() );

            // we're done with this label, so pitch it away and carry on...
            ls.remove( 0 );
        }

        // if we get here, we had to directly encode the entire domain name, so we'll need a terminating null...

        // check that we have the space in our buffer...
        if( _msgBuffer.remaining() < 1 )
            return outcome.notOk(
                    "Encoder buffer overflow",
                    new DNSResolverException( "Encoder buffer overflow", DNSResolverError.ENCODER_BUFFER_OVERFLOW )
            );

        // stuff the terminating null...
        _msgBuffer.put( (byte) 0 );

        return outcome.ok();
    }


    /**
     * Attempts to create a new instance of this class from the given sequence of labels.  If the attempt is successful, an
     * {@link Outcome Outcome&lt;DNSDomainName&gt;} that is ok and contains the new instance is returned.  Otherwise, the returned
     * {@link Outcome Outcome&lt;DNSDomainName&gt;} is not ok and contains an explanatory message.
     *
     * @param _labels The labels to create the new {@link DNSDomainName} instance from.
     * @return The {@link Outcome Outcome&lt;DNSDomainName&gt;} containing the result of this attempt.
     */
    public static Outcome<DNSDomainName> fromLabels( final List<DNSLabel> _labels ) {

        Checks.required( _labels, "labels" );

        // sum the lengths of all our labels...
        int sum = 0;
        for( DNSLabel label : _labels ) {
            sum += label.length;
        }

        // aggregate length of encoded labels, not including the null terminator, must be <= 255...
        if( sum > 255 )
            return outcome.notOk(
                    "Labels would make domain name longer than 255 bytes",
                    new DNSResolverException( "Domain name over 255 bytes", DNSResolverError.INVALID_DOMAIN_NAME )
            );

        // we're good!
        return outcome.ok( new DNSDomainName( _labels ) );
    }


    /**
     * Attempts to create a new instance of this class from the given array of labels.  If the attempt is successful, an
     * {@link Outcome Outcome&lt;DNSDomainName&gt;} that is ok and contains the new instance is returned.  Otherwise, the returned
     * {@link Outcome Outcome&lt;DNSDomainName&gt;} is not ok and contains an explanatory message.
     *
     * @param _labels The array labels to create the new {@link DNSDomainName} instance from.
     * @return The {@link Outcome Outcome&lt;DNSDomainName&gt;} containing the result of this attempt.
     */
    public static Outcome<DNSDomainName> fromLabels( final DNSLabel[] _labels ) {

        Checks.required( _labels, "labels");

        return fromLabels( Arrays.asList( _labels ) );
    }


    /**
     * Attempts to create a new instance of this class from the given string, which must be formatted as a classic dot-separated domain name (like
     * "www.cnn.com").
     *
     * @param _text The text domain name to create the new {@link DNSDomainName} instance from.
     * @return The {@link Outcome Outcome&lt;DNSDomainName&gt;} containing the result of this attempt.
     */
    public static Outcome<DNSDomainName> fromString( final String _text ) {

        Checks.required( _text, "domain name string" );

        // if we got an empty string, append a period, so we can get the root domain; to lower case for case insensitivity...
        String text = ((_text.length() == 0) ? "." : _text).toLowerCase();

        // get an array of label texts...
        String[] labelTexts = text.split( "\\." );

        // convert the label texts to DNSLabel instances...
        List<DNSLabel> labels = new ArrayList<>();
        for( String labelText : labelTexts ) {
            Outcome<DNSLabel> result = DNSLabel.fromString( labelText );
            if( !result.ok() )
                return outcome.notOk( "Couldn't create label from: " + labelText + "(" + result.msg() + ")", result.cause() );
            labels.add( result.info() );
        }

        return fromLabels( labels );
    }


    /**
     * Returns the parent domain name of this domain.  For instance, if this domain name is "www.bogus.com", this method returns the domain name
     * "bogus.com".  If this domain name is the root domain, this method throws an {@link IllegalStateException}.
     *
     * @return the parent domain name of this domain.
     */
    public DNSDomainName parent() {

        if( isRoot() )
            throw new IllegalStateException( "Cannot get parent of the root domain name" );

        return new DNSDomainName( labels.subList( 1, labels.size() ) );
    }


    /**
     * Returns {@code true} if this domain name represents the root domain.
     *
     * @return {@code true} if this domain name represents the root domain.
     */
    public boolean isRoot() {
        return labels.size() == 0;
    }


    /**
     * Returns {@code true} if this domain name represents a top level domain (TLD).
     *
     * @return {@code true} if this domain name represents a top level domain (TLD).
     */
    public boolean isTLD() {
        return labels.size() == 1;
    }


    /**
     * Returns the number of labels in this domain name.
     *
     * @return the number of labels in this domain name.
     */
    public int size() {
        return labels.size();
    }


    /**
     * Attempts to create a new instance of this class from the encoded bytes in the given DNS message {@link ByteBuffer}.  Note that because this
     * is decoding from the message, the encoding may be the compressed form; this method will decompress any such compressed encoding.
     *
     * @param _buffer The {@link ByteBuffer} containing the encoded bytes to create the new {@link DNSDomainName} instance from, starting at the current position.
     * @return The {@link Outcome Outcome&lt;DNSDomainName&gt;} containing the result of this attempt.
     */
    public static Outcome<DNSDomainName> decode( final ByteBuffer _buffer ) {

        Checks.required( _buffer );

        if( !_buffer.hasRemaining() )
            return outcome.notOk(
                    "Buffer has no bytes remaining",
                    new DNSResolverException( "Buffer underflow", DNSResolverError.DECODER_BUFFER_UNDERFLOW )
            );

        // in the case of a compressed form, we need to remember what the buffer position should be when we've finished...
        int nextPos = -1;  // impossible value; will be set the first time we run into a compression pointer (but not any subsequent ones)...

        // decode one label at a time, building up a sequence of labels...
        List<DNSLabel> labels = new ArrayList<>();
        while( _buffer.get( _buffer.position() ) != 0 ) {

            // if we have a compression pointer, follow it...
            if( 0xC0 == (0xC0 & _buffer.get( _buffer.position()) ) ) {

                // extract the 16 bit pointer...
                short offset = (short)(0x3FFF & _buffer.getShort());

                // if this is the first compression pointer we've seen, then we need to remember this position, so we can set it at the end...
                if( nextPos < 0)
                    nextPos = _buffer.position();

                // now change our position to where the compression pointer sent us to, and try again...
                _buffer.position( offset );
                continue;
            }

            // we get here for a directly encoded (i.e., not compressed) label and add it to our list...
            // note that we can get here after following a compression pointer...
            Outcome<DNSLabel> labelOutcome = DNSLabel.decode( _buffer );
            if( !labelOutcome.ok() )
                return outcome.notOk( "Could not decode label: " + labelOutcome.msg(), labelOutcome.cause() );
            labels.add( labelOutcome.info() );
        }

        // eat the terminating null...
        _buffer.get();

        // if we did any decompression, put the pointer back where it belongs...
        if( nextPos >= 0 )
            _buffer.position( nextPos );

        return fromLabels( labels );
    }


    @Override
    public boolean equals( final Object _o ) {

        if( this == _o ) return true;
        if( _o == null || getClass() != _o.getClass() ) return false;
        DNSDomainName that = (DNSDomainName) _o;
        return length == that.length && text.equals( that.text ) && labels.equals( that.labels );
    }


    @Override
    public int hashCode() {

        return Objects.hash( text, length, labels );
    }
}
