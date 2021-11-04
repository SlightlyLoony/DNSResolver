package com.dilatush.dns.examples;

import com.dilatush.dns.DNSResolver;
import com.dilatush.dns.message.DNSDomainName;
import com.dilatush.dns.message.DNSQuestion;
import com.dilatush.dns.message.DNSRRType;
import com.dilatush.dns.query.DNSQuery;
import com.dilatush.util.General;
import com.dilatush.util.Outcome;

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

        DNSResolver resolver = DNSResolver.getDefaultRecursiveResolver();

        DNSQuestion question = new DNSQuestion( DNSDomainName.fromString( "www.state.gov" ).info(), DNSRRType.A );

        resolver.query( question, Test::handler );

        sleep( 3000 );
//
//        resolver.query( question, Test::handler2 );
//
//        sleep( 100000 );

        breakpoint();
    }


    private static void handler( Outcome<DNSQuery.QueryResult> _result ) {
        LOGGER.log( Level.INFO, _result.info().log().toString() );
        breakpoint();
    }


    private static void handler2( Outcome<DNSQuery.QueryResult> _result ) {
        LOGGER.log( Level.INFO, _result.info().log().toString() );
        breakpoint();
    }
}
