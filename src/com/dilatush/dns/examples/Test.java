package com.dilatush.dns.examples;

import com.dilatush.dns.DNSResolver;
import com.dilatush.dns.DNSResolverAPI;
import com.dilatush.util.Outcome;

import java.net.InetAddress;
import java.util.List;

import static com.dilatush.util.General.breakpoint;

public class Test {

    public static void main( final String[] _args ) throws InterruptedException {

        DNSResolver.Builder builder = new DNSResolver.Builder();
        DNSResolver resolver = builder.getDNSResolver().info();

        DNSResolverAPI api = new DNSResolverAPI( resolver );

        Outcome<List<InetAddress>> qo = api.resolveIPAddresses( "www.hp.com" );
        breakpoint();
    }
}
