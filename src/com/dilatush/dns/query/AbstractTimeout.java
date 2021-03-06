package com.dilatush.dns.query;

import java.util.function.Consumer;

/**
 * Concrete instances of this class represent cancellable timeouts that call a {@link Consumer Consumer&lt;Object&gt;} if the timeout actually occurs.  The
 * companion {@link Timeouts} class manages a collection of these timeouts.
 */
@SuppressWarnings( "unused" )
public abstract class AbstractTimeout {

    private final long     expiration;       // the system time that this timeout expires...
    private       boolean  cancelled;        // true if this timeout has been cancelled...
    private       boolean  done;             // true if this timeout has expired or has been cancelled...


    /**
     * Create a new instance of this class that will expire at the given number of milliseconds in the future.
     *
     * @param _timeoutMS      The time (in milliseconds) from now that this timeout should expire.
     */
    protected AbstractTimeout( final long _timeoutMS ) {
        expiration     = System.currentTimeMillis() + _timeoutMS;  // calculating the system time at timeout expiration...
    }


    /**
     * Check to see if this timeout has expired, and if it has expired then call the timeout handler.  The timeout handler will be called no more
     * than once for each timeout.  Returns {@code true} if the timeout has expired, and {@code false} otherwise.
     *
     * @return {@code true} if this timeout has expired.
     */
    public synchronized boolean hasExpired() {

        // if we haven't yet reached our expiration time, then leave with a negative...
        if( System.currentTimeMillis() < expiration )
            return false;

        // if we're already done somehow or if we've been cancelled, return positive without doing anything...
        if( done || cancelled )
            return true;

        // looks like we actually have to expire - so call our handler...
        onTimeout();

        // mark us as done (so we don't do this again), and leave with a positive...
        done = true;
        return true;
    }


    /**
     * Invoked when a timeout occurs.
     */
    protected abstract void onTimeout();


    /**
     * Attempt to cancel this timeout, returning {@code true} if the cancellation was successful and the timeout handler will not be called, or
     * {@code false} if the cancellation failed (because the timeout has already been cancelled or because the timeout handler has already been
     * called).
     *
     * @return {@code true} if cancellation was successful, and the timeout handler will not be called.
     */
    @SuppressWarnings( "UnusedReturnValue" )
    public synchronized boolean cancel() {

        // if we've already been cancelled or expired, just return false...
        if( done )
            return false;

        // otherwise, cancel and return true...
        cancelled = true;
        done = true;
        return true;
    }


    /**
     * Returns {@code true} if this timeout has expired or has been cancelled.
     *
     * @return {@code true} if this timeout has expired or has been cancelled.
     */
    public synchronized boolean isDone() {
        return done;
    }


    /**
     * Returns the system time (the result of {@link System#currentTimeMillis()}) at which this timeout will expire.
     *
     * @return the system time (the result of {@link System#currentTimeMillis()}) at which this timeout will expire.
     */
    public long getExpiration() {
        return expiration;
    }


    /**
     * Returns {@code true} if this timeout has been cancelled.
     *
     * @return {@code true} if this timeout has been cancelled.
     */
    public synchronized boolean isCancelled() {
        return cancelled;
    }
}
