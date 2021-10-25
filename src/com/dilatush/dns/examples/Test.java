package com.dilatush.dns.examples;

import com.dilatush.dns.DNSResolver;
import com.dilatush.dns.DNSResolverAPI;
import com.dilatush.util.Outcome;
import com.dilatush.util.ip.IPv4Address;

import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.UnknownHostException;
import java.util.List;

import static com.dilatush.util.General.breakpoint;
import static com.dilatush.util.General.initLogging;

@SuppressWarnings( "unused" )
public class Test {

    public static void main( final String[] _args ) throws UnknownHostException {


        initLogging( "example-logging.properties" );

        Inet4Address ip = (Inet4Address) InetAddress.getByName( "8.8.8.8" );
        InetSocketAddress socket = new InetSocketAddress( ip, 53 );
        DNSResolverAPI api = new DNSResolverAPI( DNSResolver.getDefaultRecursiveResolver() );

        Outcome<List<IPv4Address>> result = api.resolveIPv4Addresses( "www.cnn.com" );

        breakpoint();
    }
}
