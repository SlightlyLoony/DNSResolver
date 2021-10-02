package com.dilatush.dns.misc;

import com.dilatush.util.Checks;

import static com.dilatush.dns.misc.DNSServerSelectionStrategy.*;


/**
 * Instances of this class are used by the DNS resolver when resolving in forwarding mode.  An instance defines how a recursive DNS server should be selected from a list of
 * possible recursive DNS servers.
 */
@SuppressWarnings( "unused" )
public class DNSServerSelection {

    /** The strategy to use when selecting a recursive DNS server. */
    public final DNSServerSelectionStrategy strategy;

    /** If the strategy is {@link DNSServerSelectionStrategy#NAMED}, the name of the recursive DNS server to select. */
    public final String serverName;


    /**
     * Create a new instance of this class with the given {@link DNSServerSelectionStrategy} and recursive DNS server name.  Note that this constructor is private; it is only
     * called through this class' factory methods.
     *
     * @param _strategy  The strategy to use when selecting a recursive DNS server.
     * @param _serverName The recursive DNS server name, used only if the strategy is {@link DNSServerSelectionStrategy#NAMED}.
     */
    private DNSServerSelection( final DNSServerSelectionStrategy _strategy, final String _serverName ) {
        strategy = _strategy;
        serverName = _serverName;
    }


    /**
     * Create a new instance of this class specifying that the list of possible recursive DNS servers should be randomly shuffled, then servers tried in that order until a working
     * recursive DNS server is found.
     *
     * @return The new instance of this class.
     */
    public static DNSServerSelection random() {
        return new DNSServerSelection( RANDOM, null );
    }


    /**
     * Create a new instance of this class specifying that the list of possible recursive DNS servers should be tried in the order they were specified until a working recursive
     * DNS server is found.
     *
     * @return The new instance of this class.
     */
    public static DNSServerSelection roundRobin() {
        return new DNSServerSelection( ROUND_ROBIN, null );
    }


    /**
     * Create a new instance of this class specifying that the list of possible recursive DNS servers should be sorted in order of priority (highest priority first), then servers
     * tried in that order until a working recursive DNS server is found.
     *
     * @return The new instance of this class.
     */
    public static DNSServerSelection priority() {
        return new DNSServerSelection( PRIORITY, null );
    }


    /**
     * Create a new instance of this class specifying that the list of possible recursive DNS servers should be sorted in order of their timeout value, with the lowest timeout
     * values first (the presumed fastest DNS servers), then tried in that order until a working recursive DNS server is found.
     *
     * @return The new instance of this class.
     */
    public static DNSServerSelection speed() {
        return new DNSServerSelection( SPEED, null );
    }


    /**
     * Create a new instance of this class specifying that the named recursive DNS server should be selected, and no other recursive DNS servers should be tried if it fails.  The
     * name, for this purpose, is the name used when specifying the recursive DNS server (not necessarily its domain name).
     *
     * @return The new instance of this class.
     */
    public static DNSServerSelection named( final String _serverName ) {
        Checks.notEmpty( _serverName );
        return new DNSServerSelection( RANDOM, _serverName );
    }
}
