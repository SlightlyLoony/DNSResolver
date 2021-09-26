package com.dilatush.dns.examples;

import com.dilatush.dns.DNSResolver;
import com.dilatush.dns.DNSResolverAPI;
import com.dilatush.dns.DNSServerException;
import com.dilatush.util.Outcome;

import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetSocketAddress;
import java.util.Arrays;
import java.util.List;

import static com.dilatush.util.General.breakpoint;
import static com.dilatush.util.General.initLogging;
import static java.lang.Thread.sleep;

/**
 * Resolve DNS information using both a forwarding resolver and a recursive resolver, using the asynchronous API.
 */
@SuppressWarnings( "unused" )
public class AsyncAPIExample {

    public static void main( final String[] _args ) throws InterruptedException {

        initLogging( "example-logging.properties" );

        System.out.println( "Using forwarding resolver" );

        // get an API that uses a forwarding resolver...
        DNSResolverAPI api = getForwardingResolverAPI();

        // resolve some things...
        resolve( api );

        // wait for a few seconds for all this stuff to finish...
        sleep( 5000 );

        System.out.println( "Using recursive resolver" );

        // get an API that uses a recursive resolver...
        api = getRecursiveResolverAPI();

        // resolve some things...
        resolve( api );

        // wait for a few seconds for all this stuff to finish...
        sleep( 5000 );

        breakpoint();
    }


    private static void resolve( final DNSResolverAPI _api ) {

        // get the IPv4 addresses for a few FQDNs and print the results...
        resolveIPv4( _api, "yahoo.com", "www.cnn.com", "ppp.cnn.com" );

        // get the IPv6 addresses for a few FQDNs and print the results...
        resolveIPv6( _api, "yahoo.com", "www.cnn.com", "ppp.cnn.com" );

        // get the name servers for some FQDNs and print the results...
        resolveNameServers( _api, "yahoo.com", "www.cnn.com", "qqq.cnn.com" );

        // get the text for some FQDNs and print the results...
        resolveText( _api, "yahoo.com", "www.cnn.com", "cnn.com", "google.com", "qqq.cnn.com" );
    }


    private static DNSResolverAPI getForwardingResolverAPI() {

        // create a DNS resolver that can forward to Google or Cloudflare...
        DNSResolver.Builder builder = new DNSResolver.Builder();
        builder.addDNSServer( new InetSocketAddress( "8.8.8.8", 53 ), 2000, 0, "Google"     );
        builder.addDNSServer( new InetSocketAddress( "1.1.1.1", 53 ), 1500, 0, "Cloudflare" );
        Outcome<DNSResolver> ro = builder.getDNSResolver();
        if( ro.notOk() ) {
            System.out.println( "Could not build forwarding resolver: " + ro.msg() );
            System.exit( 1 );
        }
        return new DNSResolverAPI( ro.info() );
    }


    private static DNSResolverAPI getRecursiveResolverAPI() {

        // create a DNS resolver that can forward to Google or Cloudflare...
        DNSResolver.Builder builder = new DNSResolver.Builder();
        Outcome<DNSResolver> ro = builder.getDNSResolver();
        if( ro.notOk() ) {
            System.out.println( "Could not build recursive resolver: " + ro.msg() );
            System.exit( 1 );
        }
        return new DNSResolverAPI( ro.info() );
    }


    // use the given API to resolve and print out the IPv4 addresses of the given FQDNs...
    private static void resolveIPv4( final DNSResolverAPI _api, final String... _fqdn ) {

        Arrays.stream( _fqdn ).sequential().forEach( (fqdn) -> {

            Outcome<?> ip4o = _api.resolveIPv4Addresses( new HandleIPv4( fqdn )::handler, fqdn );

            if( ip4o.ok() )
                System.out.println( "Query initiated for " + fqdn + " IPv4 addresses" );
            else
                System.out.println( "Problem initiating query for " + fqdn + " IPv4 addresses" );
        } );
    }


    private static class HandleIPv4 {

        private final String fqdn;

        private HandleIPv4( final String _fqdn ) {
            fqdn = _fqdn;
        }

        private void handler( final Outcome<List<Inet4Address>> _result ) {
            if( _result.ok() )
                if( _result.info().size() > 0 )
                    _result.info().forEach( (ip) -> System.out.println( "IPv4:      ok: " + ip.toString() ) );
                else
                    System.out.println( "IPv4:      ok: " + fqdn + " has no IPv4 addresses" );
            else
            if( _result.cause() instanceof DNSServerException )
                System.out.println( "IPv4:  not ok: " + fqdn + ": server reports " + ((DNSServerException) _result.cause()).responseCode );
            else
                System.out.println( "IPv4:  not ok: " + fqdn + ": " + _result.msg() );
        }
    }


    // use the given API to resolve and print out the IPv6 addresses of the given FQDNs...
    private static void resolveIPv6( final DNSResolverAPI _api, final String... _fqdn ) {

        Arrays.stream( _fqdn ).sequential().forEach( (fqdn) -> {

            Outcome<?> ip4o = _api.resolveIPv6Addresses( new HandleIPv6( fqdn )::handler, fqdn );

            if( ip4o.ok() )
                System.out.println( "Query initiated for " + fqdn + " IPv6 addresses" );
            else
                System.out.println( "Problem initiating query for " + fqdn + " IPv6 addresses" );
        } );
    }


    private static class HandleIPv6 {

        private final String fqdn;

        private HandleIPv6( final String _fqdn ) {
            fqdn = _fqdn;
        }

        private void handler( final Outcome<List<Inet6Address>> _result ) {
            if( _result.ok() )
                if( _result.info().size() > 0 )
                    _result.info().forEach( (ip) -> System.out.println( "IPv6:      ok: " + ip.toString() ) );
                else
                    System.out.println( "IPv6:      ok: " + fqdn + " has no IPv6 addresses" );
            else
            if( _result.cause() instanceof DNSServerException )
                System.out.println( "IPv6:  not ok: " + fqdn + ": server reports " + ((DNSServerException) _result.cause()).responseCode );
            else
                System.out.println( "IPv6:  not ok: " + fqdn + ": " + _result.msg() );
        }
    }


    // use the given API to resolve and print out the IPv4 addresses of the given FQDNs...
    private static void resolveNameServers( final DNSResolverAPI _api, final String... _fqdn ) {

        Arrays.stream( _fqdn ).sequential().forEach( (fqdn) -> {

            Outcome<?> nso = _api.resolveNameServers( new HandleNameServers( fqdn )::handler, fqdn );

            if( nso.ok() )
                System.out.println( "Query initiated for " + fqdn + " name servers" );
            else
                System.out.println( "Problem initiating query for " + fqdn + " name servers" );
        } );
    }


    private static class HandleNameServers {

        private final String fqdn;

        private HandleNameServers( final String _fqdn ) {
            fqdn = _fqdn;
        }

        private void handler( final Outcome<List<String>> _result ) {
            if( _result.ok() )
                if( _result.info().size() > 0 )
                    _result.info().forEach( (ns) -> System.out.println( "Name Server:      ok: " + fqdn + " has name server " + ns ) );
                else
                    System.out.println( "Name Server:      ok: " + fqdn + " has no name servers" );
            else
            if( _result.cause() instanceof DNSServerException )
                System.out.println( "Name Server:  not ok: " + fqdn + ": server reports " + ((DNSServerException) _result.cause()).responseCode );
            else
                System.out.println( "Name Server:  not ok: " + fqdn + ": " + _result.msg() );
        }
    }


    // use the given API to resolve and print out the TXT records of the given FQDNs...
    private static void resolveText( final DNSResolverAPI _api, final String... _fqdn ) {

        Arrays.stream( _fqdn ).sequential().forEach( (fqdn) -> {

            Outcome<?> txto = _api.resolveText( new HandleText( fqdn )::handler, fqdn );

            if( txto.ok() )
                System.out.println( "Query initiated for " + fqdn + " text" );
            else
                System.out.println( "Problem initiating query for " + fqdn + " text" );
        } );
    }


    private static class HandleText {

        private final String fqdn;

        private HandleText( final String _fqdn ) {
            fqdn = _fqdn;
        }

        private void handler( final Outcome<List<String>> _result ) {
            if( _result.ok() )
                if( _result.info().size() > 0 )
                    _result.info().forEach( (ns) -> System.out.println( "Text:      ok: " + fqdn + " has text: " + ns ) );
                else
                    System.out.println( "Text:      ok: " + fqdn + " has no text" );
            else
            if( _result.cause() instanceof DNSServerException )
                System.out.println( "Text:  not ok: " + fqdn + ": server reports " + ((DNSServerException) _result.cause()).responseCode );
            else
                System.out.println( "Text:  not ok: " + fqdn + ": " + _result.msg() );
        }
    }
}
