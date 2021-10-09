package com.dilatush.dns.examples;

import com.dilatush.dns.DNSResolver;
import com.dilatush.dns.DNSResolverAPI;
import com.dilatush.util.Outcome;

import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.UnknownHostException;
import java.util.List;

import static com.dilatush.util.General.breakpoint;

@SuppressWarnings( "unused" )
public class Test {

    public static void main( final String[] _args ) throws UnknownHostException {


        Inet4Address ip = (Inet4Address) InetAddress.getByName( "8.8.8.8" );
        InetSocketAddress socket = new InetSocketAddress( ip, 53 );
        DNSResolverAPI api = new DNSResolverAPI( DNSResolver.getDefaultForwardingResolver( socket, "Google" ) );

        long start = System.currentTimeMillis();
        Outcome<List<Inet4Address>> result = api.resolveIPv4Addresses( "www.cnn.com" );
        long firstTime = System.currentTimeMillis();
        result = api.resolveIPv4Addresses( "www.cnn.com" );
        long secondTime = System.currentTimeMillis();

        breakpoint();
    }
}
