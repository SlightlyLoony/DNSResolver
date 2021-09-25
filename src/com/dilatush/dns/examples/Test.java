package com.dilatush.dns.examples;

import com.dilatush.dns.DNSResolver;
import com.dilatush.dns.DNSUtil;
import com.dilatush.dns.agent.DNSQuery;
import com.dilatush.dns.agent.DNSTransport;
import com.dilatush.dns.message.DNSQuestion;
import com.dilatush.dns.message.DNSRRType;
import com.dilatush.util.Outcome;

import static com.dilatush.util.General.breakpoint;
import static java.lang.Thread.sleep;

public class Test {

    public static void main( final String[] _args ) throws InterruptedException {

        DNSResolver.Builder builder = new DNSResolver.Builder();
        DNSResolver resolver = builder.getDNSResolver().info();

        DNSQuestion question = DNSUtil.getQuestion( "www.cnn.com", DNSRRType.AAAA ).info();
        resolver.query( question, Test::handler1, DNSTransport.UDP );
        sleep( 3000 );
        resolver.query( question, Test::handler2, DNSTransport.UDP );

        sleep(5000);
    }


    private static void handler1( final Outcome<DNSQuery.QueryResult> _outcome ) {
        System.out.println( _outcome.info().log() );
        breakpoint();
    }


    private static void handler2( final Outcome<DNSQuery.QueryResult> _outcome ) {
        System.out.println( _outcome.info().log() );
        breakpoint();
    }
}
