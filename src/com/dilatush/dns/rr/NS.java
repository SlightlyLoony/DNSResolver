package com.dilatush.dns.rr;

//   +---------------------------+
//   | See RFC 1035 for details. |
//   +---------------------------+

import com.dilatush.dns.message.DNSDomainName;
import com.dilatush.dns.message.DNSRRClass;
import com.dilatush.dns.message.DNSRRType;
import com.dilatush.util.Checks;
import com.dilatush.util.Outcome;

import java.nio.BufferOverflowException;
import java.nio.ByteBuffer;
import java.util.Map;

/**
 * Instances of this class represent a DNS Resource Record for the domain name of the name server providing answers.
 *
 * @author Tom Dilatush  tom@dilatush.com
 */
@SuppressWarnings( "unused" )
public class NS extends DNSResourceRecord {

    private static final Outcome.Forge<NS> outcome       = new Outcome.Forge<>();

    /** The domain name of the name server providing the answers in a response. */
    public final DNSDomainName nameServer;


    /**
     * Create a new instance of this class with the given parameters.  Note that this constructor is private and is used only by factory methods and
     * decoders in this class.
     *
     * @param _name The {@link DNSDomainName} that the IP address in this class pertains to.
     * @param _klass The {@link DNSRRClass} that this resource record pertains to (in the real world, always IN for Internet).
     * @param _ttl This resource record's time-to-live (in a cache) in seconds, or zero for no caching.
     * @param _dataLength The length (in bytes) of this resource record's data (not including the resource record's header).
     * @param _nameServer The domain name of the name server providing the answers in a response.
     */
    private NS(
            final DNSDomainName _name, final DNSRRClass _klass, final long _ttl, final int _dataLength,
            final DNSDomainName _nameServer ) {

        super( new Init( _name, DNSRRType.NS, _klass, _ttl, _dataLength ) );
        nameServer = _nameServer;
    }


    /**
     * Create a new instance of this class from the given parameters.  Returns an ok outcome with the newly created instance if there were no
     * problems.  Otherwise, returns a not ok outcome with an explanatory message.
     *
     * @param _name The {@link DNSDomainName} that the IP address in this class pertains to.
     * @param _klass The {@link DNSRRClass} that this resource record pertains to (in the real world, always IN for Internet).
     * @param _ttl This resource record's time-to-live (in a cache) in seconds, or zero for no caching.
     * @param _nameServer The domain name of the name server providing the answers in a response.
     * @return The {@link Outcome Outcome&lt;NS&gt;} with the result of this method.
     */
    public static Outcome<NS> create(
            final DNSDomainName _name, final DNSRRClass _klass, final int _ttl,
            final DNSDomainName _nameServer ) {

        Checks.required( _name, _klass, _nameServer );

        return outcome.ok( new NS( _name, _klass, _ttl, 4, _nameServer ) );
    }


    /**
     * Create a new instance of this class from the given parameters, with a {@link DNSRRClass} of "IN" (Internet).  Returns an ok outcome with the
     * newly created instance if there were no problems.  Otherwise, returns a not ok outcome with an explanatory message.
     *
     * @param _name The {@link DNSDomainName} that the IP address in this class pertains to.
     * @param _ttl This resource record's time-to-live (in a cache) in seconds, or zero for no caching.
     * @param _nameServer The domain name of the name server providing the answers in a response.
     * @return The {@link Outcome Outcome&lt;CNAME&gt;} with the result of this method.
     */
    public static Outcome<NS> create(
            final DNSDomainName _name, final int _ttl,
            final DNSDomainName _nameServer ) {
        return create( _name, DNSRRClass.IN, _ttl, _nameServer );
    }


    /**
     * Decode the resource record from the given DNS message {@link ByteBuffer}. On entry, the message buffer must be positioned at the first byte
     * of this resource record's data.  On exit, the message buffer will be positioned at the first byte following the last byte encoding this resource
     * record.  Returns an ok outcome with the decoded resource record instance if the decoding encountered no problems.  Otherwise, returns a not ok
     * outcome with an explanatory message about the problem encountered.
     *
     * @param _msgBuffer The {@link ByteBuffer} to decode this resource record from.
     * @return The {@link Outcome} of the decoding operation.
     */
    protected static Outcome<NS> decode(final ByteBuffer _msgBuffer, final Init _init ) {

        // decode the domain name...
        Outcome<DNSDomainName> dnOutcome = DNSDomainName.decode( _msgBuffer );
        if( dnOutcome.notOk() )
            return outcome.notOk( dnOutcome.msg(), dnOutcome.cause() );

        // create and return our instance...
        return outcome.ok( new NS(_init.name(), _init.klass(), _init.ttl(), _init.dataLength(), dnOutcome.info() ) );
    }


    /**
     * Encode the resource data for the concrete resource record class.  On entry, the given DNS message {@link ByteBuffer} is positioned at the first
     * byte of the resource data, and the given map of name offsets contains pointers to all the previously encoded domain names.  On exit, the
     * message buffer must be positioned at the first byte following the resource data.  See {@link DNSDomainName#encode(ByteBuffer, Map)
     * DNSDomainName.encode(ByteBuffer,Map&lt;String,Integer&gt;)} for details about the message compression mechanism.  The outcome returned is ok if
     * the encoding was successful, and not ok (with a message) if there was a problem.  If the result was a buffer overflow, the outcome is not ok
     * with a cause of {@link BufferOverflowException}.
     *
     * @param _msgBuffer The {@link ByteBuffer} to encode this resource record into.
     * @param _nameOffsets The map of domain and sub-domain names that have been directly encoded, and their associated offset.
     * @return the {@link Outcome}, either ok or not ok with an explanatory message.
     */
    @Override
    protected Outcome<?> encodeChild( ByteBuffer _msgBuffer, Map<String, Integer> _nameOffsets ) {

        // encode the cname and skedaddle...
        return nameServer.encode( _msgBuffer, _nameOffsets );
    }


    /**
     * Returns {@code true} if the given {@link DNSResourceRecord} has the same resource data as this record.
     *
     * @param _rr the {@link DNSResourceRecord} to compare with this one.
     * @return {@code true} if this record's resource data is the same as the given record's resource data.
     */
    @Override
    protected boolean sameResourceData( final DNSResourceRecord _rr ) {

        return nameServer.text.equals( ((NS)_rr).nameServer.text );
    }


    /**
     * Returns a new {@link DNSResourceRecord} instance, a clone of this instance except with the given domain name.  If the new domain name is the same as the
     * * existing domain name, this instance is returned.
     *
     * @param _dn The new {@link DNSDomainName}.
     * @return A new {@link DNSResourceRecord} instance, a clone of this instance except with the given domain name.
     */
    @Override
    public DNSResourceRecord changeNameTo( final DNSDomainName _dn ) {

        Checks.required( _dn );

        // if the domain name is already the same as the given name, just return ourselves...
        if( _dn.equals( name ) )
            return this;

        // they're different, so return a new instance with the new domain name and normalized IP...
        return new NS( _dn, klass, ttl, dataLength, nameServer );
    }


    /**
     * Return a string representing this instance.
     *
     * @return a string representing this instance.
     */
    public String toString() {
        return type.name() + ": " + nameServer.text + super.toString();
    }
}
