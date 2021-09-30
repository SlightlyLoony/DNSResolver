package com.dilatush.dns.examples;

import com.dilatush.dns.DNSResolver;
import com.dilatush.dns.DNSResolverAPI;
import com.dilatush.util.Outcome;

import java.net.UnknownHostException;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Semaphore;

import static com.dilatush.util.General.breakpoint;
import static com.dilatush.util.General.initLogging;

/**
 * Using three different approaches for matching queries and results with the asynchronous API...
 */
@SuppressWarnings( "unused" )
public class AsyncApproachesExample {

    // a map of domain FQDNs to name server FQDNs...
    private static final Map<String,NameServer> fqdns = new ConcurrentHashMap<>();

    private static final Semaphore waiter = new Semaphore( 0 );

    public static void main( final String[] _args ) throws UnknownHostException, InterruptedException {

        initLogging( "example-logging.properties" );

        // get an API instance that uses a default resolver - the simplest possible case...
        DNSResolverAPI api = new DNSResolverAPI( DNSResolver.getDefaultRecursiveResolver() );


        // ** FIRST APPROACH: handler on objects ** //

        clearMap();
        api.resolver.clear();
        println( "\n--- FIRST APPROACH ---" );

        // fire off queries for each of the domains, specifying the handler on NameServer instances...
        fqdns.keySet().forEach( (fqdn) -> api.resolveNameServers( fqdns.get( fqdn )::handler, fqdn ) );

        // wait until all the queries have completed...
        waiter.acquire( fqdns.size() );

        // print the list of name server FQDNs we received...
        fqdns.forEach( (fqdn,ns) -> System.out.println( fqdn + ": " + ns ) );


        // ** SECOND APPROACH: one handler, identifier on attachment ** //

        clearMap();
        api.resolver.clear();
        println( "\n--- SECOND APPROACH ---" );

        // fire off queries for each of the domains, specifying the handler on NameServer instances...
        fqdns.keySet().forEach( (fqdn) -> api.resolveNameServers( AsyncApproachesExample::identifierHandler, fqdn, fqdn ) );

        // wait until all the queries have completed...
        waiter.acquire( fqdns.size() );

        // print the list of name server FQDNs we received...
        fqdns.forEach( (fqdn,ns) -> System.out.println( fqdn + ": " + ns ) );


        // ** THIRD APPROACH: one handler, object on attachment ** //

        clearMap();
        api.resolver.clear();
        println( "\n--- THIRD APPROACH ---" );

        // fire off queries for each of the domains, specifying the handler on NameServer instances...
        fqdns.forEach( (fqdn, ns) -> api.resolveNameServers( AsyncApproachesExample::objectHandler, fqdn, ns ) );

        // wait until all the queries have completed...
        waiter.acquire( fqdns.size() );

        // print the list of name server FQDNs we received...
        fqdns.forEach( (fqdn,ns) -> System.out.println( fqdn + ": " + ns ) );

        breakpoint();
    }


    private static void clearMap() {
        fqdns.clear();
        fqdns.put( "amd.com",    new NameServer() );
        fqdns.put( "hp.com",     new NameServer() );
        fqdns.put( "google.com", new NameServer() );
        fqdns.put( "apple.com",  new NameServer() );
        fqdns.put( "adobe.com",  new NameServer() );
        fqdns.put( "intel.com",  new NameServer() );
    }


    private static class NameServer {

        private String fqdn;

        public void setFQDN( final String _fqdn ) {
            fqdn = _fqdn;
        }

        private void handler( final Outcome<List<String>> _outcome ) {

            if( _outcome.notOk() ) {
                println( "Bad outcome: " + _outcome.msg() );
                waiter.release();
                return;
            }

            List<String> nameServers = _outcome.info();
            if( nameServers.size() > 0 ) {
                fqdn = nameServers.get( 0 );
            }

            waiter.release();
        }

        public String toString() {
            return fqdn;
        }
    }


    private static void identifierHandler( final Outcome<List<String>> _outcome, final Object _attachment ) {

        if( _outcome.notOk() ) {
            println( "Bad outcome: " + _outcome.msg() );
            waiter.release();
            return;
        }

        String key = (String) _attachment;

        List<String> nameServers = _outcome.info();
        if( nameServers.size() > 0 ) {
            String nsFQDN = nameServers.get( 0 );
            fqdns.get( key ).setFQDN( nsFQDN );
        }

        waiter.release();
    }


    private static void objectHandler( final Outcome<List<String>> _outcome, final Object _attachment ) {

        if( _outcome.notOk() ) {
            println( "Bad outcome: " + _outcome.msg() );
            waiter.release();
            return;
        }

        NameServer ns = (NameServer) _attachment;

        List<String> nameServers = _outcome.info();
        if( nameServers.size() > 0 ) {
            String nsFQDN = nameServers.get( 0 );
            ns.setFQDN( nsFQDN );
        }

        waiter.release();
    }


    private static void println( final String _msg ) {
        System.out.println( _msg );
    }
}
