package com.dilatush.dns.query;

import com.dilatush.dns.DNSResolver;
import com.dilatush.dns.message.DNSMessage;
import com.dilatush.dns.misc.DNSResolverError;
import com.dilatush.dns.misc.DNSResolverException;
import com.dilatush.util.Checks;
import com.dilatush.util.ExecutorService;
import com.dilatush.util.Outcome;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.ClosedChannelException;
import java.nio.channels.SocketChannel;
import java.util.logging.Level;
import java.util.logging.Logger;

import static com.dilatush.util.General.getLogger;
import static java.nio.channels.SelectionKey.*;


/**
 * Instances of this class implement a TCP transport channel to communicate with a specific DNS server.  The lifetime of an instance is intended to be a single query and response,
 * or a single transmitted TCP message, followed by a single received TCP message.  This might seem odd to anyone experienced with network communications, but if follows directly
 * from these things:
 * <ol>
 *     <li>Since DNS queries/responses normally start off with UDP communications, for most DNS server communications TCP is not involved at all.</li>
 *     <li>When the {@link DNSResolver} is operating in recursive mode, which the author expects to be the more common case, then there will be relatively few DNS queries being
 *     made to the same DNS server - and thus a persistent object would be useless by definition.</li>
 * </ol>
 * <p>Note that instances of this class will not create any networking objects until the {@link #send(DNSMessage)} method is called.  This "lazy initialization" ensures that
 * creating an instance of this class is as lightweight as possible.</p>
 */
public class DNSTCPChannel extends DNSChannel {

    private static final Logger        LOGGER        = getLogger();

    private final ByteBuffer           prefix = ByteBuffer.allocate( 2 );  // the TCP prefix is always two bytes long...

    protected     SocketChannel        tcpChannel;      // the socket channel for our TCP communications...
    private       ByteBuffer           inboundMessage;  // the buffer for a single incoming message...


    /**
     * Create a new instance of this class with the given parameters.  Note that creating an instance does not actually initialize the I/O at all.
     *
     * @param _query The query that owns the agent that owns this channel.
     * @param _agent The agent that owns this channel.
     * @param _nio The {@link DNSNIO} for this channel to use for network I/O.
     * @param _executor The {@link ExecutorService} for this channel to use.
     * @param _serverAddress The IP address and port for this channel to connect to.
     */
    protected DNSTCPChannel( final DNSQuery _query, final DNSServerAgent _agent, final DNSNIO _nio, final ExecutorService _executor, final InetSocketAddress _serverAddress ) {
        super( _query, _agent, _nio, _executor, _serverAddress );
    }


    /**
     * Send the given {@link DNSMessage} via this channel.  The message is sent asynchronously; this method will return immediately.  Note that this method is not synchronized,
     * but because there is a separate instance of this class per query, it doesn't need to be.
     *
     * @param _msg The {@link DNSMessage} to send.
     * @return The {@link Outcome Outcome&lt;?&gt;} of the send operation.
     */
    @Override
    protected Outcome<?> send( final DNSMessage _msg ) {

        Checks.required( _msg );

        // attempt to encode the message, leaving with errors but no further action if we failed...
        Outcome<ByteBuffer> emo = _msg.encode();
        if( emo.notOk() )
            return outcome.notOk( "Could not encode message: " + emo.msg(), emo.cause() );
        ByteBuffer encodedMsg = emo.info();

        // prepend the TCP length field (a two byte length prefix specified by the DNS RFCs)...
        // when this completes, the "data" ByteBuffer contains the entire encoded message, including the length prefix...
        ByteBuffer data = ByteBuffer.allocate( 2 + encodedMsg.limit() );
        data.putShort( (short) encodedMsg.limit() );
        if( encodedMsg.position() != 0 )
            encodedMsg.flip();
        data.put( encodedMsg );
        data.flip();

        // add the encoded message to our send queue...
        sendData.addFirst( data );

        // at this point we know that we have at least one message in the send queue - so we need to actually initialize the channel, if we haven't already done so...
        if( tcpChannel == null ) {

            try {
                tcpChannel = SocketChannel.open();       // despite the method name, this call actually creates the SocketChannel instance...
                tcpChannel.configureBlocking( false );   // this is the entire point of using NIO...
                tcpChannel.bind( null );                 // bind to an automatically selected address (only matters if the host has multiple network interfaces)...
            }

            // if something went horribly wrong, we fail with an explanation...
            catch( IOException _e ) {
                return outcome.notOk(
                        "Could not open TCP channel: " + _e.getMessage(),
                        new DNSResolverException( "Could not open TCP channel", _e, DNSResolverError.NETWORK )
                );
            }
        }

        // if we haven't already done so, connect and set write interest on...
        if( !(tcpChannel.isConnected() || tcpChannel.isConnectionPending()) ) {
            try {
                tcpChannel.connect( serverAddress );                                // this just initiates the connection; doesn't necessarily complete it...
                nio.register( this, tcpChannel, OP_WRITE | OP_READ | OP_CONNECT );  // register read, write, and connect interest...
                return outcome.ok();                                                // if we didn't get any exceptions, then all is well...
            }

            // if something went horribly wrong, we fail with an explanation...
            catch( IOException _e ) {
                return outcome.notOk(
                        "Could not send message via TCP: " + _e.getMessage(),
                        new DNSResolverException( "Could not send message via TCP", _e, DNSResolverError.NETWORK )
                );
            }
        }

        // since we've already at least initiated connection, and registered interest, we just leave happy...
        return outcome.ok();
    }


    /**
     * Write data from the send buffer to the network, addressed to this channel's server address.  This method is called from {@link DNSNIO}'s <i>IO Runner</i> thread, and should
     * never be called from anywhere else.  The work done in this method should be minimal and constrained, as it's being executed in the I/O loop.  This method must be carefully
     * coded so that it cannot throw any uncaught exceptions that would terminate the I/O loop thread.
     */
    @Override
    protected void write() {

        // get the last element in our send data queue, or null if the queue is empty...
        ByteBuffer buffer = sendData.peekLast();

        // for so long as we have a buffer to operate upon...
        while( (buffer != null) ) {

            // if the current buffer has no data to send...
            if( !buffer.hasRemaining() ) {
                sendData.pollLast();           // remove the last element of our send queue...
                buffer = sendData.peekLast();  // get the (newly) last element, or null if the queue is empty...
                continue;                      // and try this again...
            }

            // if we get here, then we have some data that needs sending...
            try {
                int bytesWritten = tcpChannel.write( buffer );  // write as much of the data as we can...
                if( bytesWritten == 0 )                         // if we couldn't write anything at all, break out of the write loop...
                    break;

            }

            // if something went wrong with the writing, then we need to close the channel and terminate the query with an error...
            catch( IOException _e ) {
                close();
                executor.submit( new Wrapper( () -> query.handleProblem(
                        "Error sending message by TCP: ",
                        new DNSResolverException( _e.getMessage(), _e, DNSResolverError.NETWORK ) )
                ) );
                return;
            }
        }

        // we get to this point if we've written everything we can at the moment - which may or may not be all the data that NEEDS to be written...
        // but if the buffer is null, then we really are out of data, and it's time to de-register our write interest...
        if( buffer == null ) {
            try {
                nio.register( this, tcpChannel, OP_READ );
            }

            // naught to do; safe to ignore...
            catch( ClosedChannelException _e ) {
                // this is here to suppress a warning from the IDE...
            }
        }
    }


    /**
     * Read data from the server this channel is addressed to, into the read buffer.  This method is called from {@link DNSNIO}'s <i>IO Runner</i> thread, and should
     * never be called from anywhere else.  The work done in this method should be minimal and constrained, as it's being executed in the I/O loop; message decoding and handling
     * must be done in another thread.  This method must be carefully coded so that it cannot throw any uncaught exceptions that would terminate the I/O loop thread.
     */
    @Override
    protected void read() {

        try {

            // if we haven't yet read the two-byte length prefix, try to do so now...
            if( prefix.hasRemaining() ) {
                tcpChannel.read( prefix );       // attempt the read...
                if( prefix.hasRemaining() )      // if we couldn't even read two bytes (this seems most unlikely!), we just leave...
                    return;
                LOGGER.finest( "Read TCP prefix: " + (prefix.getShort( 0 ) & 0xFFFF) );
            }

            // we get here if we HAVE read the prefix, and now we need to read the actual message...
            // if the inbound message buffer is null, that means we haven't yet created it -- so do so...
            if( inboundMessage == null ) {

                // get the message length out of the prefix (that's what it's for!)...
                prefix.flip();
                int messageLength = prefix.getShort() & 0xFFFF;

                // now allocate a buffer of the right size for the actual message...
                inboundMessage = ByteBuffer.allocate( messageLength );
                LOGGER.finest( "Made TCP message buffer: " + (prefix.getShort( 0 ) & 0xFFFF) );
            }

            // we get here if we've read the prefix, and we've created a buffer for our message...
            // we could get here with the message partially read on an earlier call to this method...
            // in either case, we need to read some more data, so here we go...
            if( tcpChannel.read( inboundMessage ) != 0 ) {

                // if we just read the entire message, then we need to actually do something with it...
                if( !inboundMessage.hasRemaining() ) {

                    // prepare the buffer and send it to the agent for decoding and handling...
                    inboundMessage.flip();
                    LOGGER.finest( "Got message: " + inboundMessage.limit() );
                    ByteBuffer msg = inboundMessage;     // this makes a copy of the reference for the lambda below...
                    executor.submit( new Wrapper( () -> agent.handleReceivedData( msg, DNSTransport.TCP ) ) );

                    // now we've finished with this message, so we clear the two buffers in preparation for a possible following message...
                    inboundMessage = null;
                    prefix.clear();
                }
            }
        }

        // if something goes wrong while reading, we need to close the channel and report an error on the query...
        catch( IOException _e ) {
            close();
            executor.submit( new Wrapper( () -> query.handleProblem(
                    "Error receiving message by TCP: ",
                    new DNSResolverException( _e.getMessage(), _e, DNSResolverError.NETWORK ) )
            ) );
        }
    }


    /**
     * Close this channel.
     */
    @Override
    protected void close() {

        try {
            if( (tcpChannel != null) && tcpChannel.isOpen() )
                tcpChannel.close();
        }
        catch( IOException _e ) {
            LOGGER.log( Level.WARNING, "Exception when closing TCP channel", _e );
        }
        tcpChannel = null;
    }
}
