package com.dilatush.dns.query;

import com.dilatush.dns.misc.DNSResolverError;
import com.dilatush.dns.misc.DNSResolverException;
import com.dilatush.dns.message.DNSMessage;
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

public class DNSTCPChannel extends DNSChannel {

    private static final Logger        LOGGER        = getLogger();

    public        SocketChannel        tcpChannel;
    private final ByteBuffer           prefix = ByteBuffer.allocate( 2 );
    private       ByteBuffer           message;


    protected DNSTCPChannel( final DNSQuery _query, final DNSServerAgent _agent, final DNSNIO _nio, final ExecutorService _executor, final InetSocketAddress _serverAddress ) {
        super( _query, _agent, _nio, _executor, _serverAddress );
    }


    @Override
    protected Outcome<?> send( final DNSMessage _msg ) {

        Checks.required( _msg );

        Outcome<ByteBuffer> emo = _msg.encode();
        if( emo.notOk() )
            return outcome.notOk( "Could not encode message: " + emo.msg(), emo.cause() );
        ByteBuffer encodedMsg = emo.info();

        // prepend the TCP length field...
        ByteBuffer data = ByteBuffer.allocate( 2 + encodedMsg.limit() );
        data.putShort( (short) encodedMsg.limit() );
        if( encodedMsg.position() != 0 )
            encodedMsg.flip();
        data.put( encodedMsg );
        data.flip();

        boolean wasAdded = sendData.offerFirst( data );
        if( !wasAdded )
            return outcome.notOk( "TCP send data queue full", new DNSResolverException( "TCP send data queue full", DNSResolverError.TCP_SEND_QUEUE_FULL ) );

        if( tcpChannel == null ) {
            try {
                tcpChannel = SocketChannel.open();
                tcpChannel.configureBlocking( false );
                tcpChannel.bind( null );
            }
            catch( IOException _e ) {
                return outcome.notOk(
                        "Could not open TCP channel: " + _e.getMessage(),
                        new DNSResolverException( "Could not open TCP channel", _e, DNSResolverError.NETWORK )
                );
            }
        }

        // if we just added the first data, connect and set write interest on...
        if( !(tcpChannel.isConnected() || tcpChannel.isConnectionPending()) ) {
            try {
                tcpChannel.connect( serverAddress );
                nio.register( this, tcpChannel, OP_WRITE | OP_READ | OP_CONNECT );
                return outcome.ok();
            }
            catch( IOException _e ) {
                return outcome.notOk(
                        "Could not send message via TCP: " + _e.getMessage(),
                        new DNSResolverException( "Could not send message via TCP", _e, DNSResolverError.NETWORK )
                );
            }
        }

        return outcome.ok();
    }


    @Override
    protected void write() {

        ByteBuffer buffer = sendData.peekLast();

        while( (buffer != null) ) {

            if( !buffer.hasRemaining() ) {
                sendData.pollLast();
                buffer = sendData.peekLast();
                continue;
            }

            try {
                int bytesWritten = tcpChannel.write( buffer );
                if( bytesWritten == 0 )
                    break;

            } catch( IOException _e ) {
                close();
                executor.submit( new Wrapper( () -> query.handleProblem(
                        "Error sending message by TCP: ",
                        new DNSResolverException( _e.getMessage(), _e, DNSResolverError.NETWORK ) )
                ) );
                return;
            }
        }

        if( sendData.isEmpty() ) {
            try {
                nio.register( this, tcpChannel, OP_READ );
            } catch( ClosedChannelException _e ) {
                // naught to do; safe to ignore...
            }
        }
    }


    @Override
    protected void read() {

        try {
            if( prefix.hasRemaining() ) {
                tcpChannel.read( prefix );
                if( prefix.hasRemaining() ) {
                    return;
                }
                LOGGER.finest( "Read TCP prefix: " + (prefix.getShort( 0 ) & 0xFFFF) );
            }
            if( message == null ) {
                prefix.flip();
                int messageLength = prefix.getShort() & 0xFFFF;
                message = ByteBuffer.allocate( messageLength );
                LOGGER.finest( "Made TCP message buffer: " + (prefix.getShort( 0 ) & 0xFFFF) );
            }
            if( tcpChannel.read( message ) != 0 ) {
                if( !message.hasRemaining() ) {
                    message.flip();
                    LOGGER.finest( "Got message: " + message.limit() );
                    ByteBuffer msg = message;
                    executor.submit( new Wrapper( () -> agent.handleReceivedData( msg, DNSTransport.TCP ) ) );
                    message = null;
                    prefix.clear();
                    close();
                }
            }
        }
        catch( IOException _e ) {
            close();
            executor.submit( new Wrapper( () -> query.handleProblem(
                    "Error receiving message by TCP: ",
                    new DNSResolverException( _e.getMessage(), _e, DNSResolverError.NETWORK ) )
            ) );
        }
    }


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
