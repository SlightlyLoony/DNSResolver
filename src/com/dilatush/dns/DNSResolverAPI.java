package com.dilatush.dns;

import com.dilatush.dns.agent.DNSTransport;
import com.dilatush.util.Checks;
import com.dilatush.util.General;
import com.dilatush.util.Outcome;
import com.dilatush.dns.message.DNSQuestion;
import com.dilatush.dns.message.DNSRRType;

import java.net.Inet4Address;
import java.util.List;
import java.util.concurrent.Semaphore;
import java.util.function.Consumer;
import java.util.logging.Logger;

import static com.dilatush.dns.DNSUtil.extractIPv4Addresses;
import static com.dilatush.dns.agent.DNSQuery.QueryResult;
import static com.dilatush.dns.agent.DNSTransport.UDP;

/**
 * <p>Instances of this class wrap an instance of {@link DNSResolver} to provide a simpler and more convenient API than is provided by the {@link DNSResolver} itself.</p>
 * <p>If the wrapped {@link DNSResolver} has been provisioned with DNS servers that it can forward to, then this API will forward all its queries to those DNS servers.
 * Which DNS server will be used is determined by the {@link DNSServerSelection} configured in the instance of this class.  By default that will be to select the fastest
 * server (as determined by the timeout value associated with it), but any strategy may be chosen (see {@link #DNSResolverAPI(DNSResolver,DNSServerSelection)}).</p>
 * <p>If the wrapped {@link DNSResolver} has not been provisioned with any DNS servers that it can forward to, then this API will resolve all its queries by recursively
 * querying authoritative DNS servers, starting with the DNS root servers.  This approach is sometimes called iterative resolution as well.</p>
 * <p>The RFCs defining the DNS wire protocols require queries to first be transmitted over UDP, then if the response is truncated because of the size limitation (512
 * bytes) of a UDP response, then the query can be resent over TCP (which has no response size limitation).  The author has read that some DNS servers will in fact refuse
 * an initial query over TCP, though he has not seen that himself.  By default this API will always use UDP as the initial query transport, however, this behavior can
 * be changed (see {@link #DNSResolverAPI(DNSResolver,DNSServerSelection,DNSTransport)}</p>
 *
 * @author Tom Dilatush  tom@dilatush.com
 */
@SuppressWarnings( "unused" )
public class DNSResolverAPI {

    private static final Logger LOGGER = General.getLogger();

    private static final Outcome.Forge<?>                  outcome     = new Outcome.Forge<>();
    private static final Outcome.Forge<List<Inet4Address>> ipv4Outcome = new Outcome.Forge<>();

    /** The {@link DNSResolver} wrapped by this instance. */
    public final DNSResolver        resolver;

    /** The server selection strategy (for forwarded queries) used by this instance. */
    public final DNSServerSelection serverSelection;

    /** The initial transport (UDP or TCP) for queries made through this instance. */
    public final DNSTransport initialTransport;


    /**
     * Creates a new instance of this class, wrapping the given {@link DNSResolver} instance.  If the wrapped resolver has DNS servers configured that it can forward to, which
     * server is used will be determined by the strategy in the given {@link DNSServerSelection}.  The initial transport used for queries will be the given {@link DNSTransport}.
     *
     * @param _resolver The {@link DNSResolver} wrapped by this instance.
     * @param _serverSelection The {@link DNSServerSelection} strategy that will be used by this instance when forwarding queries.
     * @param _initialTransport The initial transport (UDP or TCP) used for the queries made through this instance.
     */
    public DNSResolverAPI( final DNSResolver _resolver, final DNSServerSelection _serverSelection, final DNSTransport _initialTransport ) {
        Checks.required( _resolver, _serverSelection, _initialTransport );
        resolver         = _resolver;
        serverSelection  = _serverSelection;
        initialTransport = _initialTransport;
    }


    /**
     * Creates a new instance of this class, wrapping the given {@link DNSResolver} instance.  If the wrapped resolver has DNS servers configured that it can forward to, which
     * server is used will be determined by the strategy in the given {@link DNSServerSelection}.  The initial transport used for queries will be UDP.
     *
     * @param _resolver The {@link DNSResolver} wrapped by this instance.
     * @param _serverSelection The {@link DNSServerSelection} strategy that will be used by this instance when forwarding queries.
     */
    public DNSResolverAPI( final DNSResolver _resolver, final DNSServerSelection _serverSelection ) {
        this( _resolver, _serverSelection, UDP );
    }


    /**
     * Creates a new instance of this class, wrapping the given {@link DNSResolver} instance.  If the wrapped resolver has DNS servers configured that it can forward to, which
     * server is used will be the server's speed (the one configured with the smallest timeout value will be used first).  The initial transport used for queries will be UDP.
     *
     * @param _resolver The {@link DNSResolver} wrapped by this instance.
     */
    public DNSResolverAPI( final DNSResolver _resolver ) {
        this( _resolver, DNSServerSelection.speed() );
    }


    /**
     * <p>Asynchronously resolve the Internet Protocol version 4 (IPv4) addresses for the given fully-qualified domain name (FQDN), calling the given handler with the result.</p>
     * <p>Returns a "not ok" outcome if there was a problem initiating network operations to transmit the query to a DNS server.</p>
     * <p>Note that it is possible for the handler to be called with the results in the caller's thread, before this method returns.  This is especially the case for any query
     * that was resolved from the resolver's cache.  The outcome argument to the handler will be "not ok" if there was a problem querying other DNS servers, or if the FQDN does
     * not exist.  Otherwise, it will be "ok", and the information will be a list of zero or more IPv4 addresses.</p>
     *
     * @param _handler  The {@link Consumer Consumer&lt;Outcome&lt;List&lt;Inet4Address&gt;&gt;&gt;} handler that will be called with the result of this query.
     * @param _fqdn The FQDN (such as "www.google.com") to resolve into one or more IPv4 addresses.
     * @return The {@link Outcome Outcome&lt;?&gt;} that is "not ok" only if there was a problem initiating the query.
     */
    public Outcome<?> resolveIPv4Addresses( final Consumer<Outcome<List<Inet4Address>>> _handler, final String _fqdn  ) {

        Checks.required( _fqdn, _handler );

        Outcome<DNSQuestion> qo = DNSUtil.getQuestion( _fqdn, DNSRRType.A );
        if( qo.notOk() )
            return outcome.notOk( qo.msg(), qo.cause() );
        DNSQuestion question = qo.info();
        IPv4Handler handler = new IPv4Handler( _handler );
        return query( question, handler::handler );
    }


    /**
     * Synchronously resolve the Internet Protocal version 4 (IPv4) addresses for the given fully-qualified domain name (FQDN), returning an
     * {@link Outcome Outcome&lt;List&lt;Inet4Address&gt;&gt;} with the result.  The outcome will be "not ok" if there was a problem querying other DNS servers, or if the FQDN
     * does not exist.  Otherwise, it will be "ok", and the information will be a list of zero or more IPv4 addresses.
     *
     * @param _fqdn The FQDN (such as "www.google.com") to resolve into one or more IPv4 addresses.
     * @return The {@link Outcome Outcome&lt;List&lt;Inet4Address&gt;&gt;} with the result of this query.
     */
    public Outcome<List<Inet4Address>> resolveIPv4Addresses( final String _fqdn ) {

        Checks.required( _fqdn );

        Outcome<DNSQuestion> qo = DNSUtil.getQuestion( _fqdn, DNSRRType.A );
        if( qo.notOk() )
            return ipv4Outcome.notOk( qo.msg(), qo.cause() );

        SyncHandler handler = new SyncHandler();
        DNSQuestion question = qo.info();
        query( question, handler::handler );
        handler.waitForCompletion();

        return handler.qr.ok()
                ? ipv4Outcome.ok( extractIPv4Addresses( handler.qr.info().response().answers ) )
                : ipv4Outcome.notOk( handler.qr.msg(), handler.qr.cause() );
    }


    /**
     * <p>Queries (through the wrapped {@link DNSResolver} instance) to resolve the given {@link DNSQuestion} asynchronously, calling the given handler with the result.  If the
     * query is resolved from cache, then the handler will be called in the caller's thread (before this method returns). Otherwise, the handler will be called in another thread.
     * If the wrapped {@link DNSResolver} instance has DNS servers provisioned, then the query will be forwarded to one of those.  Otherwise, the query will be resolved
     * recursively by the wrapped resolver.</p>
     * <p>The result of this call will be ok unless there is some problem with transmitting the query over the network.</p>
     *
     * @param _question The {@link DNSQuestion} to be resolved.
     * @param _handler The {@link Consumer Consumer&lt;Outcome&lt;QueryResult&gt;&gt;} handler that will be called with the result of the query.
     * @return The outcome of this query.
     */
    private Outcome<?> query( final DNSQuestion _question, final Consumer<Outcome<QueryResult>> _handler ) {

        // which query method we call on the resolver depends on whether we're forwarding or recursively resolving...
        if( resolver.hasServers() ) {

            // make the forwarding call...
            return resolver.query( _question, _handler, initialTransport, serverSelection );
        }
        else {

            // make the recursive call...
            return resolver.query( _question, _handler, initialTransport );
        }
    }


    /**
     *
     */
    private static class IPv4Handler {

        private final Consumer<Outcome<List<Inet4Address>>> ipv4Handler;
        private       Outcome<QueryResult> qr;

        private IPv4Handler( final Consumer<Outcome<List<Inet4Address>>> _ipv4Handler ) {
            ipv4Handler = _ipv4Handler;
        }

        private void handler( final Outcome<QueryResult> _qr ) {

            ipv4Handler.accept(
                    _qr.ok()
                    ? ipv4Outcome.ok( extractIPv4Addresses( _qr.info().response().answers ))
                    : ipv4Outcome.notOk( _qr.msg(), _qr.cause() )
            );
        }
    }


    private static class SyncHandler {

        private Outcome<QueryResult> qr;
        private final Semaphore waiter = new Semaphore( 0 );

        private void handler( final Outcome<QueryResult> _qr ) {
            qr = _qr;
            waiter.release();
        }

        private void waitForCompletion() {
            try {
                waiter.acquire();
            } catch( InterruptedException _e ) {
                // naught to do...
            }
        }
    }
}
