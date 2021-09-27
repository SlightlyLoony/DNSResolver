package com.dilatush.dns.query;

import com.dilatush.dns.DNSResolver;
import com.dilatush.dns.DNSResolverError;
import com.dilatush.dns.DNSResolverException;
import com.dilatush.dns.message.DNSMessage;
import com.dilatush.util.Checks;
import com.dilatush.util.ExecutorService;
import com.dilatush.util.Outcome;

import java.io.IOException;
import java.net.DatagramSocket;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.ClosedChannelException;
import java.nio.channels.DatagramChannel;
import java.util.logging.Level;
import java.util.logging.Logger;

import static com.dilatush.util.General.getLogger;
import static java.nio.channels.SelectionKey.OP_READ;
import static java.nio.channels.SelectionKey.OP_WRITE;


/**
 * Instances of this class implement a UDP transport channel to communicate with a specific DNS server.  The lifetime of an instance is intended to be a single query and response,
 * or a single transmitted UDP packet, followed by a single received UDP packet.  This might seem odd to anyone experienced with network communications, but if follows directly
 * from these things:
 * <ol>
 *     <li>Since DNS queries/responses normally start off with UDP communications, there is no "connection" as there is with TCP.  Establishing a UDP NIO channel is quite a
 *     lightweight operation, so there is little benefit to keeping the {@link DatagramChannel} and its associated {@link DatagramSocket} in memory, or in the complexity of
 *     the code required to manage such a persistent object.</li>
 *     <li>When the {@link DNSResolver} is operating in recursive mode, which the author expects to be the more common case, then there will be relatively few DNS queries being
 *     made to the same DNS server - and thus a persistent object would be useless by definition.</li>
 * </ol>
 * <p>Note that instances of this class will not create any networking objects until the {@link #send(DNSMessage)} method is called.  This "lazy initialization" ensures that
 * creating an instance of this class is as lightweight as possible.</p>
 */
public class DNSUDPChannel extends DNSChannel {

    private static final Logger LOGGER = getLogger();

    private DatagramChannel udpChannel;  // the DatagramChannel that implements the UDP communications for this instance...


    /**
     * Creates a new instance of this class with the given parameters.
     *
     * @param _query The query that owns the agent that owns this channel.
     * @param _agent The agent that owns this channel.
     * @param _nio The {@link DNSNIO} for this channel to use for network I/O.
     * @param _executor The {@link ExecutorService} for this channel to use.
     * @param _serverAddress The IP address and port for this channel to connect to.
     */
    public DNSUDPChannel( final DNSQuery _query, final DNSServerAgent _agent, final DNSNIO _nio, final ExecutorService _executor, final InetSocketAddress _serverAddress ) {
        super( _query, _agent, _nio, _executor, _serverAddress );
    }


    /**
     * Send the given {@link DNSMessage} via this channel.  The message is sent asynchronously; this method will return immediately.
     *
     * @param _msg The {@link DNSMessage} to send.
     * @return The {@link Outcome Outcome&lt;?&gt;} of the send operation.
     */
    @Override
    protected synchronized Outcome<?> send( final DNSMessage _msg ) {

        Checks.required( _msg );

        // encode (serialize) our message into a new byte buffer...
        Outcome<ByteBuffer> emo = _msg.encode();
        if( emo.notOk() )
            return outcome.notOk( "Could not encode message: " + emo.msg(), emo.cause() );

        // push the encoded message into the send data queue...
        boolean wasAdded = sendData.offerFirst( emo.info() );
        if( !wasAdded )
            return outcome.notOk(
                    "UDP send data queue full",
                    new DNSResolverException( "UDP send data queue full", DNSResolverError.UDP_SEND_QUEUE_FULL )
            );

        // if we just added the first data, open the UDP socket, bind, connect, and set write interest on...
        // note that because the lifetime of an instance of this class is a single query, this should ALWAYS be true...
        if( sendData.size() == 1 ) {

            try {
                udpChannel = DatagramChannel.open();                      // this actually creates the socket and channel...
                udpChannel.configureBlocking( false );                    // this is the entire point of using NIO!
                udpChannel.bind( null );                                  // we don't care what interface will be used...
                udpChannel.connect( serverAddress );                      // there's no actual connection with UDP; this just constrains this channel to the given server...
                nio.register( this, udpChannel, OP_WRITE | OP_READ );     // this tells NIO that we want to read and write to this channel...
                return outcome.ok();                                      // we only get here if there were no problems in the code above...
            }
            catch( IOException _e ) {
                return outcome.notOk(
                        "Could not send message via UDP: " + _e.getMessage(),
                        new DNSResolverException( "Could not send message via UDP", _e, DNSResolverError.NETWORK )
                );
            }
        }

        return outcome.ok();
    }


    /**
     * Write data from the send buffer to the network, addressed to this channel's server address.  This method is called from {@link DNSNIO}'s <i>IO Runner</i> thread, and should
     * never be called from anywhere else.  The work done in this method should be minimal and constrained, as it's being executed in the I/O loop.  This method must be carefully
     * coded so that it cannot throw any uncaught exceptions that would terminate the I/O loop thread.
     */
    @Override
    protected void write() {

        // get the next packet of data to send (null if there was none)...
        ByteBuffer buffer = sendData.pollLast();

        // if we had some data to send, then send it...
        if( buffer != null ) {

            try {
                udpChannel.write( buffer );  // we ignore the number of bytes written, as it will always be the entire UDP message in a single packet...
            }

            // we had some I/O problem (unlikely with UDP, but possible, and not recoverable)...
            catch( IOException _e ) {
                close();
                executor.submit( new Wrapper( () -> query.handleProblem(
                        "Error sending message by UDP: ",
                        new DNSResolverException( _e.getMessage(), _e, DNSResolverError.NETWORK ) )
                ) );
                return;
            }
        }

        if( sendData.isEmpty() ) {
            try {
                nio.register( this, udpChannel, OP_READ );
            } catch( ClosedChannelException _e ) {
                // naught to do here; it's safe to ignore this...
            }
        }
    }


    @Override
    protected void read() {

        try {
            ByteBuffer readData = ByteBuffer.allocate( 512 );

            if( udpChannel.read( readData ) == 0 )
                return;

            readData.flip();
            executor.submit( new Wrapper( () -> agent.handleReceivedData( readData, DNSTransport.UDP ) ) );
        }

        catch( IOException _e ) {
            close();
            executor.submit( new Wrapper( () -> query.handleProblem(
                    "Error receiving message by UDP: ",
                    new DNSResolverException( _e.getMessage(), _e, DNSResolverError.NETWORK ) )
            ) );
        }
    }


    @Override
    protected void close() {

        try {
            if( udpChannel != null )
                udpChannel.close();
        }
        catch( IOException _e ) {
            LOGGER.log( Level.WARNING, "Exception when closing UDP channel", _e );
        }
    }
}
