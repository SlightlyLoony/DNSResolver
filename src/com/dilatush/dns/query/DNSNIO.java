package com.dilatush.dns.query;

import com.dilatush.dns.DNSResolver;
import com.dilatush.dns.misc.DNSResolverException;
import com.dilatush.util.ExecutorService;
import com.dilatush.util.General;

import java.io.IOException;
import java.nio.channels.ClosedChannelException;
import java.nio.channels.SelectableChannel;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.util.Iterator;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;

import static com.dilatush.dns.misc.DNSResolverError.NETWORK;
import static java.lang.System.currentTimeMillis;


/**
 * A single instance of this class manages the network I/O in a single thread for a {@link DNSResolver} instance.  Note that instances of {@link DNSChannel} and its subclasses
 * are called by this class's <i>IO Runner</i> thread to do the actual work of connecting (for TCP), reading from, and writing to the network.
 */
public class DNSNIO {

    final static private Logger    LOGGER = General.getLogger();

    private static final long      TIMEOUT_CHECK_INTERVAL_MILLIS = 50;

    private        final Selector  selector;         // the Selector where DNSChannels register their I/O interests...
    private        final Thread    ioRunner;         // the single "IO Runner" thread that does all the actual network I/O...
    private        final Timeouts  timeouts;         // the collection of active timeouts...


    /**
     * Creates a new instance of this class.  The new instance will start a daemon thread that does the bulk of the work of this class, which is to handle the low-level (UDP and
     * TCP) I/O for the DNS resolver.  By default, received data and timeout handlers are called through a single-threaded {@link ExecutorService} instance (with a daemon thread
     * and a queue of 100).
     *
     * @throws DNSResolverException if the selector can't be opened for some reason.
     */
    public DNSNIO() throws DNSResolverException {

        // get our timeouts manager...
        timeouts = new Timeouts();

        // open the selector we're going to use for all our I/O...
        try {
            selector = Selector.open();
        }
        catch( IOException _e ) {
            throw new DNSResolverException( "Problem opening selector", _e, NETWORK );
        }

        // create and start our I/O thread...
        ioRunner = new Thread( this::ioLoop );
        ioRunner.setDaemon( true );
        ioRunner.setName( "IO Runner" );
        ioRunner.start();
    }


    /**
     * Register the given operations (as defined by {@link SelectableChannel#register(Selector,int,Object)}) for the given {@link SelectableChannel} on this instance's selector.
     * The given {@link DNSChannel} will be attached.
     *
     * @param _dnsChannel The {@link DNSChannel} to attach.
     * @param _channel The {@link SelectableChannel} to register operations for.
     * @param _operations The operations to register (see {@link SelectableChannel#register(Selector,int,Object)}).
     * @throws ClosedChannelException if the channel is closed.
     */
    protected void register( final DNSChannel _dnsChannel, final SelectableChannel _channel, final int _operations ) throws ClosedChannelException {
        _channel.register( selector, _operations, _dnsChannel );
    }


    /**
     * Add the given timeout to the collection of active timeouts.
     *
     * @param _timeout The timeout to add.
     */
    protected void addTimeout( final AbstractTimeout _timeout ) {
        timeouts.add( _timeout );
    }


    /**
     * The main I/O loop for {@link DNSServerAgent}s.  In normal operation the {@code while()} loop will run forever.
     */
    private void ioLoop() {

        // the earliest system time that we should do a timeout check...
        long nextTimeoutCheck = currentTimeMillis() + TIMEOUT_CHECK_INTERVAL_MILLIS;

        // we're going to loop here basically forever...
        while( !ioRunner.isInterrupted() ) {

            // any exceptions in this code are a serious problem; if we get one, we just log it and make no attempt to recover...
            try {

                // select and get any keys, but timeout when it's next time to check our timeouts...
                selector.select( nextTimeoutCheck - currentTimeMillis() );

                // iterate over any selected keys, and handle them...
                Set<SelectionKey> keys = selector.selectedKeys();
                Iterator<SelectionKey> keyIterator = keys.iterator();
                while( keyIterator.hasNext() ) {

                    // get the next key, extract and safely cast its attachment...
                    SelectionKey key = keyIterator.next();
                    DNSTCPChannel tcp  = (key.attachment() instanceof DNSTCPChannel) ? (DNSTCPChannel) key.attachment() : null;
                    DNSChannel channel = (key.attachment() instanceof DNSChannel)    ? (DNSChannel)    key.attachment() : null;

                    // handle connecting (TCP only)...
                    if( key.isValid() && key.isConnectable() && (tcp != null) )
                        tcp.tcpChannel.finishConnect();

                    // handle writing to the network...
                    if( key.isValid() && key.isWritable() && (channel != null) )
                        channel.write();

                    // handle reading from the network...
                    if( key.isValid() && key.isReadable() && (channel != null) )
                        channel.read();

                    // get rid the key we just processed...
                    keyIterator.remove();
                }

                // see if it's time for us to check the timeouts...
                if( currentTimeMillis() >= nextTimeoutCheck ) {

                    // check 'em...
                    timeouts.check();

                    // figure out when we should check again...
                    nextTimeoutCheck = currentTimeMillis() + TIMEOUT_CHECK_INTERVAL_MILLIS;
                }
            }

            // getting here means something seriously wrong happened; log and let the loop die...
            catch( Throwable _e ) {

                LOGGER.log( Level.SEVERE, "Unhandled exception in NIO selector loop", _e );

                // this will cause the IO Runner thread to exit, and all I/O will cease...
                break;
            }
        }
    }
}
