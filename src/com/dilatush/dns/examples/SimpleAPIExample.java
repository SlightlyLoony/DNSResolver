package com.dilatush.dns.examples;

import com.dilatush.dns.DNSResolver;
import com.dilatush.dns.DNSResolverAPI;
import com.dilatush.util.Outcome;
import com.dilatush.util.ip.IPv4Address;

import java.util.List;

import static com.dilatush.util.General.breakpoint;
import static com.dilatush.util.General.initLogging;

/**
 * Simple example using a default resolver and the synchronous API.
 */
@SuppressWarnings( "unused" )
public class SimpleAPIExample {

    public static void main( final String[] _args ) {

        initLogging( "example-logging.properties" );

        // get an API instance that uses a default resolver - the simplest possible case...
        DNSResolverAPI api = new DNSResolverAPI( DNSResolver.getDefaultRecursiveResolver() );

        // get the IP addresses for the FQDN "yahoo.com"...
        Outcome<List<IPv4Address>> ipo = api.resolveIPv4Addresses( "yahoo.com" );

        // check to see whether the resolution succeeded or failed...
        if( ipo.ok() ) {

            // print the list of addresses we received...
            System.out.println( ipo.info().size() + " IPv4 addresses:" );
            ipo.info().forEach( (ip) -> System.out.println( "  " + ip.toString() ) );
        }
        else {

            // print the error message...
            System.out.println( ipo.msg() );
        }

        breakpoint();
    }
}
