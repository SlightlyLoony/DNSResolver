package com.dilatush.dns.agent;

import com.dilatush.dns.message.DNSMessage;
import com.dilatush.util.Checks;
import com.dilatush.util.ExecutorService;
import com.dilatush.util.General;
import com.dilatush.util.Outcome;

import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * The abstract base class for {@link DNSUDPChannel} and {@link DNSTCPChannel}.
 */
public abstract class DNSChannel {

    private   static final Logger LOGGER = General.getLogger();

    protected static final Outcome.Forge<?> outcome = new Outcome.Forge<>();


    protected        final DNSServerAgent    agent;          // the agent that owns this channel...
    protected        final DNSNIO            nio;            // the NIO for this channel to use...
    protected        final ExecutorService   executor;       // the executor for this channel to use...
    protected        final Deque<ByteBuffer> sendData;       // the send buffer for this channel...
    protected        final InetSocketAddress serverAddress;  // the IP and port for this channel to connect to...


    /**
     * Create a new instance of this base class with the given parameters.
     *
     * @param _agent The agent that owns this channel.
     * @param _nio The {@link DNSNIO} for this channel to use for network I/O.
     * @param _executor The {@link ExecutorService} for this channel to use.
     * @param _serverAddress The IP address and port for this channel to connect to.
     */
    protected DNSChannel( final DNSServerAgent _agent, final DNSNIO _nio, final ExecutorService _executor, final InetSocketAddress _serverAddress ) {

        Checks.required( _agent, _nio, _executor, _serverAddress );

        agent         = _agent;
        nio           = _nio;
        executor      = _executor;
        serverAddress = _serverAddress;
        sendData      = new ArrayDeque<>();
    }


    /**
     * Send the given {@link DNSMessage} via this channel.  The message is sent asynchronously; this method will return immediately.
     *
     * @param _msg The {@link DNSMessage} to send.
     * @return The {@link Outcome Outcome&lt;?&gt;} of the send operation.
     */
    protected abstract Outcome<?> send( final DNSMessage _msg );

    protected abstract void       write();
    protected abstract void       read();
    protected abstract void       close();


    /**
     * Instances of this class wrap other {@link Runnable} instances to provide exception catching and logging.
     */
    protected static class Wrapper implements Runnable {

        private final Runnable task;

        protected Wrapper( final Runnable _task ) {
            task = _task;
        }


        @Override
        public void run() {

            try {
                task.run();
            }
            catch( final Exception _e ) {
                LOGGER.log( Level.SEVERE, "Exception thrown in ExecutorService task", _e );
            }
        }
    }
}
