package com.dilatush.dns.examples;

import com.dilatush.dns.DNSResolver;
import com.dilatush.dns.DNSResolverAPI;
import com.dilatush.dns.message.DNSRRType;
import com.dilatush.dns.rr.DNSResourceRecord;
import com.dilatush.util.Outcome;

import java.util.List;

import static com.dilatush.util.General.breakpoint;
import static java.lang.Thread.sleep;

public class Test {

    public static void main( final String[] _args ) throws InterruptedException {

        DNSResolver.Builder builder = new DNSResolver.Builder();
        DNSResolver resolver = builder.getDNSResolver().info();

        DNSResolverAPI api = new DNSResolverAPI( resolver );

        Outcome<?> qo = api.resolve( Test::handler, "hp.com", DNSRRType.ANY );

        Outcome<List<DNSResourceRecord>> rro = api.resolve( "cnn.com", DNSRRType.ANY );

        sleep(5000);
        breakpoint();
    }


    public static void handler( Outcome<List<DNSResourceRecord>> _outcome ) {
        breakpoint();
    }
}
