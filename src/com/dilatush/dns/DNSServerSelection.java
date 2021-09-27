package com.dilatush.dns;

import com.dilatush.util.Checks;

import static com.dilatush.dns.DNSServerSelectionStrategy.*;

public class DNSServerSelection {

    public final DNSServerSelectionStrategy strategy;
    public final String serverName;


    private DNSServerSelection( final DNSServerSelectionStrategy _strategy, final String _serverName ) {

        strategy = _strategy;
        serverName = _serverName;
    }


    public static DNSServerSelection random() {
        return new DNSServerSelection( RANDOM, null );
    }


    public static DNSServerSelection roundRobin() {
        return new DNSServerSelection( ROUND_ROBIN, null );
    }


    public static DNSServerSelection priority() {
        return new DNSServerSelection( PRIORITY, null );
    }


    public static DNSServerSelection speed() {
        return new DNSServerSelection( SPEED, null );
    }


    public static DNSServerSelection named( final String _serverName ) {

        Checks.notEmpty( _serverName );
        return new DNSServerSelection( RANDOM, _serverName );
    }
}
