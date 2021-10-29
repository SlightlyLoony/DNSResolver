package com.dilatush.dns.examples;

import com.dilatush.dns.DNSResolver;
import com.dilatush.dns.message.DNSDomainName;
import com.dilatush.dns.message.DNSQuestion;
import com.dilatush.dns.message.DNSRRType;
import com.dilatush.dns.misc.DNSServerSelection;
import com.dilatush.dns.query.DNSQuery;
import com.dilatush.dns.query.DNSTransport;
import com.dilatush.util.Outcome;

import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.UnknownHostException;

import static com.dilatush.util.General.breakpoint;
import static com.dilatush.util.General.initLogging;
import static java.lang.Thread.sleep;

@SuppressWarnings( "unused" )
public class Test {

    public static void main( final String[] _args ) throws UnknownHostException, InterruptedException {


        initLogging( "example-logging.properties" );

        Inet4Address ip = (Inet4Address) InetAddress.getByName( "8.8.8.111" );
        InetSocketAddress socket = new InetSocketAddress( ip, 53 );

        DNSResolver resolver = DNSResolver.getDefaultForwardingResolver( socket, "Google" );

        DNSQuestion question = new DNSQuestion( DNSDomainName.fromString( "xyz.cnn.com" ).info(), DNSRRType.ANY );

        resolver.query( question, Test::handler, DNSTransport.UDP, DNSServerSelection.speed() );

        sleep( 10000 );

        breakpoint();
    }


    private static void handler( Outcome<DNSQuery.QueryResult> _result ) {
        breakpoint();
    }
}
