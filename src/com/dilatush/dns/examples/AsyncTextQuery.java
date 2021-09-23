package com.dilatush.dns.examples;

import com.dilatush.dns.DNSResolver;
import com.dilatush.dns.DNSResolverAPI;
import com.dilatush.util.ExecutorService;
import com.dilatush.util.Outcome;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Semaphore;

import static com.dilatush.util.General.breakpoint;

/**
 * Create a very simple DNS resolver that uses recursive resolution, and use it to resolve text records.
 */
@SuppressWarnings( "unused" )
public class AsyncTextQuery {

    private final static Semaphore                waiter  = new Semaphore( 0 );
    private final static List<List<String>>       results = new ArrayList<>();

    public static void main( final String[] _args ) throws InterruptedException {

        System.getProperties().setProperty( "java.util.logging.config.file", "logging.properties" );

        // create a DNS resolver that doesn't know about any other resolvers...
        DNSResolver.Builder builder = new DNSResolver.Builder();
        builder.setExecutor( new ExecutorService( 2, 100 ) );
        Outcome<DNSResolver> ro = builder.getDNSResolver();
        if( ro.notOk() ) {
            System.out.println( "Could not build resolver: " + ro.msg() );
            return;
        }
        DNSResolver resolver = ro.info();

        // wrap it with an API...
        DNSResolverAPI api = new DNSResolverAPI( resolver );

        // get all the text records from cnn.com (which we know has a bunch)...
        Outcome<?> qo = api.resolveText( AsyncTextQuery::handler, "cnn.com" );
        if( qo.notOk() ) throw new IllegalStateException( "Unexpected result from query" );
        waiter.acquire();

        // now get all the text records from www.cnn.com (which we know has none)...
        qo = api.resolveText( AsyncTextQuery::handler, "www.cnn.com" );
        if( qo.notOk() ) throw new IllegalStateException( "Unexpected result from query" );
        waiter.acquire();



//        long startTime = System.currentTimeMillis();
//        Outcome<?> qo = api.resolveIPv4Addresses( AsyncTextQuery::handler, "www.cnn.com" );
//        if( qo.notOk() ) throw new IllegalStateException( "Unexpected result from query" );
//        waiter.acquire();
//        System.out.println( "First time: " + (System.currentTimeMillis() - startTime) );
//        startTime = System.currentTimeMillis();
//        qo = api.resolveIPv4Addresses( AsyncTextQuery::handler, "www.cnn.com" );  // we're ignoring the return value, which should always be "ok"...
//        if( qo.notOk() ) throw new IllegalStateException( "Unexpected result from query" );
//        waiter.acquire();
//        System.out.println( "Second time: " + (System.currentTimeMillis() - startTime) );
//
//        // now do a bunch of concurrent resolutions...
//        String[] domains = new String[] {
//                "www.cnn.com",
//                "rock.dilatush.com",
//                "www.hp.com",
//                "www.servicenow.com",
//                "www.paradiseweather.info",
//                "news.google.com",
//                "www.qq.com",
//                "www.burger.com",
//                "www.hamburger.com",
//                "www.hp.co.uk"
//        };
//        Iterator<String> it = Arrays.stream( domains ).iterator();
//        while( it.hasNext() ) {
//            qo = api.resolveIPv4Addresses( AsyncTextQuery::handler, it.next() );
//            if( qo.notOk() ) throw new IllegalStateException( "Unexpected result from query" );
//        }
//        waiter.acquire( domains.length );
//        results.forEach( (ipa) -> {if( ipa != null ) System.out.println( ipa.toString());} );

        breakpoint();
    }

    private static void handler( final Outcome<List<String>> _outcome ) {
        if( _outcome.notOk() ) {
            System.out.println( _outcome.msg() );
            waiter.release();
            return;
        }
        results.add( _outcome.info() );
        _outcome.info().forEach( (ip) -> System.out.println( ip.toString() ) );
        waiter.release();
        breakpoint();
    }
}
