package com.dilatush.dns.examples;

import com.dilatush.dns.DNSResolver;
import com.dilatush.dns.DNSResolverAPI;
import com.dilatush.dns.DNSServerException;
import com.dilatush.util.Outcome;

import java.net.Inet4Address;
import java.net.InetSocketAddress;
import java.util.Arrays;
import java.util.List;

import static com.dilatush.util.General.breakpoint;

/**
 * Resolve DNS information using a forwarding resolver and the synchronous API.
 */
@SuppressWarnings( "unused" )
public class SyncAPIExample {

    public static void main( final String[] _args ) {

        System.getProperties().setProperty( "java.util.logging.config.file", "example-logging.properties" );

        System.out.println( "Using forwarding resolver..." );

        // get an API that uses a forwarding resolver...
        DNSResolverAPI api = getForwardingResolverAPI();

        // resolve some stuff...
        resolve( api );

        System.out.println( "Using recursive resolver" );

        // get an API that uses a recursive resolver...
        api = getRecursiveResolverAPI();

        // resolve some stuff...
        resolve( api );

        breakpoint();
    }


    private static void resolve( final DNSResolverAPI _api ) {

        // get the IPv4 addresses for a few FQDNs and print the results...
        resolveIPv4( _api, "yahoo.com", "www.cnn.com", "ppp.cnn.com" );

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

        System.out.println( "Resolved IPv4 addresses:" );

        Arrays.stream( _fqdn ).sequential().forEach( (fqdn) -> {

            Outcome<List<Inet4Address>> ip4o = _api.resolveIPv4Addresses( fqdn );
            if( ip4o.ok() )
                if( ip4o.info().size() > 0 )
                    ip4o.info().forEach( (ip) -> System.out.println( "      ok: " + ip.toString() ) );
                else
                    System.out.println( "      ok: " + fqdn + " has no IPv4 addresses" );
            else
                if( ip4o.cause() instanceof DNSServerException )
                    System.out.println( "  not ok: " + fqdn + ": server reports " + ((DNSServerException) ip4o.cause()).responseCode );
                else
                    System.out.println( "  not ok: " + fqdn + ": " + ip4o.msg() );
        } );
    }


    // use the given API to resolve and print out the IPv4 addresses of the given FQDNs...
    private static void resolveNameServers( final DNSResolverAPI _api, final String... _fqdn ) {

        System.out.println( "Resolved name servers:" );

        Arrays.stream( _fqdn ).sequential().forEach( (fqdn) -> {

            Outcome<List<String>> nso = _api.resolveNameServers( fqdn );
            if( nso.ok() )
                if( nso.info().size() > 0 )
                    nso.info().forEach( (ns) -> System.out.println( "      ok: " + fqdn + " has name server " + ns ) );
                else
                    System.out.println( "      ok: " + fqdn + " has no name servers" );
            else
                if( nso.cause() instanceof DNSServerException )
                    System.out.println( "  not ok: " + fqdn + ": server reports " + ((DNSServerException) nso.cause()).responseCode );
                else
                    System.out.println( "  not ok: " + fqdn + ": " + nso.msg() );
        } );
    }


    // use the given API to resolve and print out the TXT records of the given FQDNs...
    private static void resolveText( final DNSResolverAPI _api, final String... _fqdn ) {

        System.out.println( "Resolved text:" );

        Arrays.stream( _fqdn ).sequential().forEach( (fqdn) -> {

            Outcome<List<String>> txto = _api.resolveText( fqdn );
            if( txto.ok() )
                if( txto.info().size() > 0 )
                    txto.info().forEach( (text) -> System.out.println( "      ok: " + fqdn + " has text: " + text ) );
                else
                    System.out.println( "      ok: " + fqdn + " has no text" );
            else
                if( txto.cause() instanceof DNSServerException )
                    System.out.println( "  not ok: " + fqdn + ": server reports " + ((DNSServerException) txto.cause()).responseCode );
                else
                    System.out.println( "  not ok: " + fqdn + ": " + txto.msg() );
        } );
    }
}
