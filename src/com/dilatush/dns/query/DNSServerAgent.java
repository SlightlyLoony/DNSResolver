package com.dilatush.dns.query;

import com.dilatush.dns.DNSResolver;
import com.dilatush.dns.message.DNSMessage;
import com.dilatush.util.Bytes;
import com.dilatush.util.Checks;
import com.dilatush.util.ExecutorService;
import com.dilatush.util.Outcome;

import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.logging.Level;
import java.util.logging.Logger;

import static com.dilatush.util.General.getLogger;


/**
 * Implements an asynchronous resolver for DNS queries to a particular DNS server.  Any number of resolvers can be instantiated concurrently, but
 * only one resolver for each DNS server.  Each resolver can process any number of queries concurrently.  Each resolver can connect using either UDP
 * or TCP (normally UDP, but switching to TCP as needed).  All resolver I/O is performed by a single thread owned by the singleton
 * {@link DNSNIO}, which is instantiated on demand (when any {@link DNSServerAgent} is instantiated).
 *
 * @author Tom Dilatush  tom@dilatush.com
 */
public class DNSServerAgent {

    private static final long MIN_TIMEOUT_MILLIS = 5;
    private static final long MAX_TIMEOUT_MILLIS = 15000;

    private static final Logger LOGGER = getLogger();

    private   static final Outcome.Forge<DNSServerAgent> createOutcome = new Outcome.Forge<>();
    private   static final Outcome.Forge<DNSQuery>       queryOutcome  = new Outcome.Forge<>();

    private          final DNSUDPChannel                 udpChannel;
    private          final DNSTCPChannel                 tcpChannel;
    private          final ExecutorService               executor;
    private          final DNSResolver                   resolver;
    private          final DNSQuery                      query;
    private          final DNSNIO                        nio;

    private                DNSQueryTimeout               timeout;

    public           final long                          timeoutMillis;
    public           final int                           priority;
    public           final String                        name;


    public DNSServerAgent( final DNSResolver _resolver, final DNSQuery _query, final DNSNIO _nio, final ExecutorService _executor, final DNSResolver.ServerSpec _params ) {
        this( _resolver, _query, _nio, _executor, _params.timeoutMillis(), _params.priority(), _params.name(), _params.serverAddress() );
    }


    public DNSServerAgent( final DNSResolver _resolver, final DNSQuery _query, final DNSNIO _nio, final ExecutorService _executor,
                           final long _timeoutMillis, final int _priority, final String _name, final InetSocketAddress _serverAddress ) {

        Checks.required( _resolver, _query, _nio, _executor, _name, _serverAddress );

        if( (_timeoutMillis < MIN_TIMEOUT_MILLIS) || (_timeoutMillis > MAX_TIMEOUT_MILLIS) )
            throw new IllegalArgumentException( "Timeout outside permissible range of [" + MIN_TIMEOUT_MILLIS + ".." + MAX_TIMEOUT_MILLIS + "] milliseconds: " + _timeoutMillis );

        resolver         = _resolver;
        query            = _query;
        nio              = _nio;
        executor         = _executor;
        timeoutMillis    = _timeoutMillis;
        priority         = _priority;
        name             = _name;

        udpChannel = new DNSUDPChannel( query, this, nio, executor, _serverAddress );
        tcpChannel = new DNSTCPChannel( query, this, nio, executor, _serverAddress );
    }

    protected Outcome<?> sendQuery( final DNSMessage _queryMsg, final DNSTransport _transport ) {
        Outcome<?> result = switch( _transport ) {
            case UDP -> udpChannel.send( _queryMsg );
            case TCP -> tcpChannel.send( _queryMsg );
        };
        if( result.ok() ) {
            timeout = new DNSQueryTimeout( timeoutMillis, this::handleTimeout );
            nio.addTimeout( timeout );
        }
        return result;
    }


    protected void close() {
        timeout.cancel();
        udpChannel.close();
        tcpChannel.close();
    }


    private void handleTimeout() {
        query.handleProblem( "Query timed out before response was received", new DNSTimeoutException( "Query timed out" ) );
    }


    /**
     * Handles decoding and processing received data (which may be from either a UDP channel or a TCP channel).  The given {@link ByteBuffer} must contain exactly one full
     * message, without the TCP length prefix
     *
     * @param _receivedData
     * @param _transport
     */
    protected void handleReceivedData( final ByteBuffer _receivedData, final DNSTransport _transport ) {

        timeout.cancel();

        Outcome<DNSMessage> messageOutcome = DNSMessage.decode( _receivedData );

        if( messageOutcome.notOk() ) {
            close();
            query.handleProblem( "Could not decode received DNS message", null );

            // log the bytes we could not decode...
            byte[] badBytes = Arrays.copyOfRange( _receivedData.array(), 0, _receivedData.limit() );
            LOGGER.log( Level.WARNING, "Cannot decode received message:\n" + Bytes.bytesToString( badBytes) );

            // the commented-out code below is a convenient way to debug messages that cannot be decoded...
//            _receivedData.position( 0 );
//            DNSMessage.decode( _receivedData );
            return;
        }

        DNSMessage message = messageOutcome.info();

        query.handleResponse( message, _transport );
    }
}
