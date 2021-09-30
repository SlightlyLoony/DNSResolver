package com.dilatush.dns.examples;

import com.dilatush.dns.DNSResolver;
import com.dilatush.dns.DNSResolverAPI;
import com.dilatush.util.Outcome;

import java.net.Inet4Address;
import java.net.UnknownHostException;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Semaphore;

import static com.dilatush.util.General.breakpoint;
import static com.dilatush.util.General.initLogging;

/**
 * Simple example using a default resolver, the synchronous API with attachments.
 */
@SuppressWarnings( "unused" )
public class SimpleAsyncAttachmentAPIExample {

    private static final Map<String,Inet4Address> fqdns = new ConcurrentHashMap<>();

    private static final Semaphore waiter = new Semaphore( 0 );

    public static void main( final String[] _args ) throws UnknownHostException, InterruptedException {

        initLogging( "example-logging.properties" );

        // get an API instance that uses a default resolver - the simplest possible case...
        DNSResolverAPI api = new DNSResolverAPI( DNSResolver.getDefaultRecursiveResolver() );

        // make a map with a few FQDNs in it; we want to resolve these to IP addresses.  We start by putting 0.0.0.0 as the address, 'cause we know that isn't real...
        Inet4Address naught = (Inet4Address) Inet4Address.getByName( "0.0.0.0" );
        fqdns.put( "www.amd.com",    naught );
        fqdns.put( "www.hp.com",     naught );
        fqdns.put( "www.google.com", naught );
        fqdns.put( "www.apple.com",  naught );
        fqdns.put( "www.adobe.com",  naught );
        fqdns.put( "www.intel.com",  naught );

        // fire off queries for each of the above FQDNs, in each case attaching the FQDN as the key...
        // we're using the asynchronous API, so these will all resolve concurrently...
        fqdns.keySet().forEach( (fqdn) -> api.resolveIPv4Addresses( SimpleAsyncAttachmentAPIExample::handler, fqdn, fqdn ) );

        // wait until all the queries have completed...
        waiter.acquire( fqdns.size() );

        // print the list of IPv4 addresses we received...
        fqdns.forEach( (fqdn,ip) -> System.out.println( fqdn + ": " + ip.getHostAddress() ) );

        breakpoint();
    }


    private static void handler( final Outcome<List<Inet4Address>> _outcome, final Object _attachment ) {

        // if we had a bad outcome, print the reason and leave...
        if( _outcome.notOk() ) {
            System.out.println( "Bad outcome: " + _outcome.msg() );
            waiter.release();
            return;
        }

        // we know the attachment is a string FQDN...
        String fqdn = (String) _attachment;

        // get our list of IPv4 addresses...
        List<Inet4Address> ips = _outcome.info();

        // if we got at least one address, update the map with it...
        if( ips.size() > 0 ) {
            fqdns.put( fqdn, ips.get( 0 ) );
        }

        waiter.release();
    }
}
