package com.dilatush.dns.agent;

import com.dilatush.dns.message.DNSMessage;
import com.dilatush.util.Checks;
import com.dilatush.util.ExecutorService;
import com.dilatush.util.General;
import com.dilatush.util.Outcome;

import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.ClosedChannelException;
import java.nio.channels.Selector;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.logging.Level;
import java.util.logging.Logger;

public abstract class DNSChannel {

    private static final Logger LOGGER = General.getLogger();

    protected static final Outcome.Forge<?> outcome = new Outcome.Forge<>();


    protected final DNSServerAgent    agent;
    protected final DNSNIO            nio;
    protected final ExecutorService   executor;
    protected final Deque<ByteBuffer> sendData;
    protected final InetSocketAddress serverAddress;


    protected DNSChannel( final DNSServerAgent _agent, final DNSNIO _nio, final ExecutorService _executor, final InetSocketAddress _serverAddress ) {

        Checks.required( _agent, _nio, _executor, _serverAddress );

        agent         = _agent;
        nio           = _nio;
        executor      = _executor;
        serverAddress = _serverAddress;
        sendData      = new ArrayDeque<>();
    }


    protected abstract Outcome<?> send( final DNSMessage _msg );

    protected abstract void register( final Selector _selector, final int _operations, final Object _attachment ) throws ClosedChannelException;

    protected abstract void write();
    protected abstract void read();
    protected abstract void close();


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
