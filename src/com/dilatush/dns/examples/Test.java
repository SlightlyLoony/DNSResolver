package com.dilatush.dns.examples;

import com.dilatush.dns.DNSResolver;
import com.dilatush.dns.message.DNSDomainName;
import com.dilatush.dns.message.DNSQuestion;
import com.dilatush.dns.message.DNSRRType;
import com.dilatush.dns.misc.DNSServerSelection;
import com.dilatush.dns.query.DNSQuery;
import com.dilatush.util.General;
import com.dilatush.util.Outcome;

import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.UnknownHostException;
import java.util.logging.Level;
import java.util.logging.Logger;

import static com.dilatush.util.General.breakpoint;
import static com.dilatush.util.General.initLogging;
import static java.lang.Thread.sleep;

@SuppressWarnings( "unused" )
public class Test {

    private static Logger LOGGER;

    public static void main( final String[] _args ) throws UnknownHostException, InterruptedException {


        initLogging( "example-logging.properties" );
        LOGGER = General.getLogger();

        DNSResolver.Builder builder = new DNSResolver.Builder();
        Inet4Address ip = (Inet4Address) InetAddress.getByName( "1.1.1.1" );
        InetSocketAddress socket = new InetSocketAddress( ip, 53 );
        builder.addDNSServer( socket, 1000, 0, "CloudFlare" );
        ip = (Inet4Address) InetAddress.getByName( "8.8.8.8" );
        socket = new InetSocketAddress( ip, 53 );
        builder.addDNSServer( socket, 1000, 0, "Google" );

        DNSResolver resolver = builder.getDNSResolver().info();

        DNSQuestion question = new DNSQuestion( DNSDomainName.fromString( "zzz.cnn.com" ).info(), DNSRRType.A );

        resolver.query( question, Test::handler, DNSServerSelection.speed() );

        sleep( 10000 );
    }


    private static void handler( Outcome<DNSQuery.QueryResult> _result ) {
        LOGGER.log( Level.INFO, _result.info().log().toString() );
        breakpoint();
    }
}
