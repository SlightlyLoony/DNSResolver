package com.dilatush.dns.query;

import com.dilatush.dns.message.DNSMessage;
import com.dilatush.util.Checks;
import com.dilatush.util.ExecutorService;
import com.dilatush.util.General;
import com.dilatush.util.Outcome;

import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.util.Deque;
import java.util.concurrent.ConcurrentLinkedDeque;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * The abstract base class for {@link DNSUDPChannel} and {@link DNSTCPChannel}.
 */
public abstract class DNSChannel {

    private   static final Logger LOGGER = General.getLogger();

    protected static final Outcome.Forge<?> outcome = new Outcome.Forge<>();


    protected        final DNSQuery          query;          // the query that owns the agent that owns this channel...
    protected        final DNSServerAgent    agent;          // the agent that owns this channel...
    protected        final DNSNIO            nio;            // the NIO for this channel to use...
    protected        final ExecutorService   executor;       // the executor for this channel to use...
    protected        final Deque<ByteBuffer> sendData;       // the send buffer for this channel...
    protected        final InetSocketAddress serverAddress;  // the IP and port for this channel to connect to...


    /**
     * Create a new instance of this base class with the given parameters.
     *
     * @param _query The query that owns the agent that owns this channel.
     * @param _agent The agent that owns this channel.
     * @param _nio The {@link DNSNIO} for this channel to use for network I/O.
     * @param _executor The {@link ExecutorService} for this channel to use.
     * @param _serverAddress The IP address and port for this channel to connect to.
     */
    protected DNSChannel( final DNSQuery _query, final DNSServerAgent _agent, final DNSNIO _nio, final ExecutorService _executor, final InetSocketAddress _serverAddress ) {

        Checks.required( _query, _agent, _nio, _executor, _serverAddress );

        query         = _query;
        agent         = _agent;
        nio           = _nio;
        executor      = _executor;
        serverAddress = _serverAddress;
        sendData      = new ConcurrentLinkedDeque<>();
    }


    /**
     * Send the given {@link DNSMessage} via this channel.  The message is sent asynchronously; this method will return immediately.
     *
     * @param _msg The {@link DNSMessage} to send.
     * @return The {@link Outcome Outcome&lt;?&gt;} of the send operation.
     */
    protected abstract Outcome<?> send( final DNSMessage _msg );


    /**
     * Write data from the send buffer to the network, addressed to this channel's server address.  This method is called from {@link DNSNIO}'s <i>IO Runner</i> thread, and should
     * never be called from anywhere else.  The work done in this method should be minimal and constrained, as it's being executed in the I/O loop.  This method must be carefully
     * coded so that it cannot throw any uncaught exceptions that would terminate the I/O loop thread.
     */
    protected abstract void       write();


    /**
     * Read data from the server this channel is addressed to, into the read buffer.  This method is called from {@link DNSNIO}'s <i>IO Runner</i> thread, and should
     * never be called from anywhere else.  The work done in this method should be minimal and constrained, as it's being executed in the I/O loop; message decoding and handling
     * must be done in another thread.  This method must be carefully coded so that it cannot throw any uncaught exceptions that would terminate the I/O loop thread.
     */
    protected abstract void       read();


    /**
     * Close this channel.
     */
    protected abstract void       close();


    /**
     * Instances of this class wrap other {@link Runnable} instances to provide exception catching and logging.  Primarily this addresses an issue with {@link ExecutorService},
     * to wit: if an exception is thrown by a task it is running, the exception is silently caught and ignored, and the thread running the task does not die.  This makes debugging
     * quite the challenge.  This wrapper is intended to solve that problem.
     */
    protected static class Wrapper implements Runnable {

        private final Runnable task;  // the Runnable that we're wrapping...


        /**
         * Create a new instance of this class that wraps the given {@link Runnable}.
         *
         * @param _task The {@link Runnable} task to be wrapped.
         */
        protected Wrapper( final Runnable _task ) {
            task = _task;
        }


        /**
         * The wrapper's {@link Runnable} implementation, which does nothing except catch any thrown exceptions and log them.
         */
        @Override
        public void run() {

            try {
                task.run();   // run the wrapped task...
            }

            // if any exception is thrown by the wrapped task, catch it and log it...
            catch( final Exception _e ) {
                LOGGER.log( Level.SEVERE, "Exception thrown in ExecutorService task", _e );
            }
        }
    }
}
