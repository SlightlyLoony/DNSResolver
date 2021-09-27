package com.dilatush.dns;

import com.dilatush.dns.agent.DNSTransport;
import com.dilatush.dns.message.DNSQuestion;
import com.dilatush.dns.message.DNSRRType;
import com.dilatush.dns.rr.DNSResourceRecord;
import com.dilatush.util.Checks;
import com.dilatush.util.General;
import com.dilatush.util.Outcome;

import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Semaphore;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Consumer;
import java.util.function.Function;
import java.util.logging.Logger;

import static com.dilatush.dns.DNSUtil.*;
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
    private static final Outcome.Forge<List<InetAddress>>  ipOutcome   = new Outcome.Forge<>();

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
     * <p>Asynchronously resolve the {@link DNSResourceRecord}s of the given {@link DNSRRType} for the given fully-qualified domain name (FQDN), calling the given handler with
     * the result.  Note that the type may be {@link DNSRRType#ANY}, which will cause <i>all</i> resource records for the given FQDN to be resolved.</p>
     * <p>Returns a "not ok" outcome if there was a problem initiating network operations to transmit the query to a DNS server.</p>
     * <p>Note that it is possible for the handler to be called with the results in the caller's thread, before this method returns.  This is especially the case for any query
     * that was resolved from the resolver's cache.  The outcome argument to the handler will be "not ok" if there was a problem querying other DNS servers, or if the FQDN does
     * not exist.  Otherwise, it will be "ok", and the information will be a list of zero or more {@link DNSResourceRecord}s.</p>
     *
     * @param _handler  The {@link Consumer Consumer&lt;Outcome&lt;List&lt;DNSResourceRecord&gt;&gt;&gt;} handler that will be called with the result of this query.
     * @param _fqdn The FQDN (such as "www.google.com") to resolve into zero or more DNS resource records.
     * @param _type The {@link DNSRRType} of resource records to resolve.
     * @return The {@link Outcome Outcome&lt;?&gt;} that is "not ok" only if there was a problem initiating the query.
     */
    public Outcome<?> resolve( final Consumer<Outcome<List<DNSResourceRecord>>> _handler, final String _fqdn, final DNSRRType _type ) {

        Checks.required( _fqdn, _handler, _type );

        // set up the handler that will process the raw results of the query...
        AsyncHandler<List<DNSResourceRecord>> handler = new AsyncHandler<>( _handler, (qr) -> qr.response().answers );

        // get the question we're going to ask the DNS...
        Outcome<DNSQuestion> qo = DNSUtil.getQuestion( _fqdn, _type );
        if( qo.notOk() ) return outcome.notOk( qo.msg(), qo.cause() );

        // fire off the query...
        return query( qo.info(), handler::handler );
    }


    /**
     * <p>Asynchronously resolve the Internet Protocol version 4 (IPv4) addresses for the given fully-qualified domain name (FQDN), calling the given handler with the result.</p>
     * <p>Returns a "not ok" outcome if there was a problem initiating network operations to transmit the query to a DNS server.</p>
     * <p>Note that it is possible for the handler to be called with the results in the caller's thread, before this method returns.  This is especially the case for any query
     * that was resolved from the resolver's cache.  The outcome argument to the handler will be "not ok" if there was a problem querying other DNS servers, or if the FQDN does
     * not exist.  Otherwise, it will be "ok", and the information will be a list of zero or more IPv4 addresses.</p>
     *
     * @param _handler  The {@link Consumer Consumer&lt;Outcome&lt;List&lt;Inet4Address&gt;&gt;&gt;} handler that will be called with the result of this query.
     * @param _fqdn The FQDN (such as "www.google.com") to resolve into zero or more IPv4 addresses.
     * @return The {@link Outcome Outcome&lt;?&gt;} that is "not ok" only if there was a problem initiating the query.
     */
    public Outcome<?> resolveIPv4Addresses( final Consumer<Outcome<List<Inet4Address>>> _handler, final String _fqdn  ) {

        Checks.required( _fqdn, _handler );

        // set up the handler that will process the raw results of the query...
        AsyncHandler<List<Inet4Address>> handler = new AsyncHandler<>( _handler, (qr) -> extractIPv4Addresses( qr.response().answers, _fqdn ) );

        // get the question we're going to ask the DNS...
        Outcome<DNSQuestion> qo = DNSUtil.getQuestion( _fqdn, DNSRRType.A );
        if( qo.notOk() ) return outcome.notOk( qo.msg(), qo.cause() );

        // fire off the query...
        return query( qo.info(), handler::handler );
    }


    /**
     * <p>Asynchronously resolve the Internet Protocol version 6 (IPv6) addresses for the given fully-qualified domain name (FQDN), calling the given handler with the result.</p>
     * <p>Returns a "not ok" outcome if there was a problem initiating network operations to transmit the query to a DNS server.</p>
     * <p>Note that it is possible for the handler to be called with the results in the caller's thread, before this method returns.  This is especially the case for any query
     * that was resolved from the resolver's cache.  The outcome argument to the handler will be "not ok" if there was a problem querying other DNS servers, or if the FQDN does
     * not exist.  Otherwise, it will be "ok", and the information will be a list of zero or more IPv6 addresses.</p>
     *
     * @param _handler  The {@link Consumer Consumer&lt;Outcome&lt;List&lt;Inet6Address&gt;&gt;&gt;} handler that will be called with the result of this query.
     * @param _fqdn The FQDN (such as "www.google.com") to resolve into zero or more IPv6 addresses.
     * @return The {@link Outcome Outcome&lt;?&gt;} that is "not ok" only if there was a problem initiating the query.
     */
    public Outcome<?> resolveIPv6Addresses( final Consumer<Outcome<List<Inet6Address>>> _handler, final String _fqdn  ) {

        Checks.required( _fqdn, _handler );

        // set up the handler that will process the raw results of the query...
        AsyncHandler<List<Inet6Address>> handler = new AsyncHandler<>( _handler, ( qr) -> extractIPv6Addresses( qr.response().answers, _fqdn ) );

        // get the question we're going to ask the DNS...
        Outcome<DNSQuestion> qo = DNSUtil.getQuestion( _fqdn, DNSRRType.AAAA );
        if( qo.notOk() ) return outcome.notOk( qo.msg(), qo.cause() );

        // fire off the query...
        return query( qo.info(), handler::handler );
    }


    /**
     * <p>Asynchronously resolve the Internet Protocol addresses (both version 4 and 6) for the given fully-qualified domain name (FQDN), calling the given handler with the
     * result.  Note that this operation requires two queries.</p>
     * <p>Returns a "not ok" outcome if there was a problem initiating network operations to transmit either query to a DNS server.</p>
     * <p>Note that it is possible for the handler to be called with the results in the caller's thread, before this method returns.  This is especially the case for any query
     * that was resolved from the resolver's cache.  The outcome argument to the handler will be "not ok" if there was a problem querying other DNS servers, or if the FQDN does
     * not exist.  Otherwise, it will be "ok", and the information will be a list of zero or more IP addresses.</p>
     *
     * @param _handler  The {@link Consumer Consumer&lt;Outcome&lt;List&lt;Inet6Address&gt;&gt;&gt;} handler that will be called with the result of this query.
     * @param _fqdn The FQDN (such as "www.google.com") to resolve into zero or more IP addresses.
     * @return The {@link Outcome Outcome&lt;?&gt;} that is "not ok" only if there was a problem initiating the query.
     */
    public Outcome<?> resolveIPAddresses( final Consumer<Outcome<List<InetAddress>>> _handler, final String _fqdn  ) {

        Checks.required( _fqdn, _handler );

        // where we're going to stuff the results...
        List<InetAddress> result = new ArrayList<>();

        // where we keep track of whether we've already received one result...
        AtomicInteger resultCount = new AtomicInteger();

        // We must make two separate queries to get the answers, as DNS has no ability to query for both A and AAAA at once.  We're doing this asynchronously, so we make
        // both queries at once, then wait until we get two answers.  We return with an error if either query had errors being sent...

        // create our special handlers, to receive both IPv4 and IPv6 results...
        Consumer<Outcome<List<Inet4Address>>> handler4 = (ipso) -> {
            if( ipso.ok() )
                handleIPResults( _handler, ipso.info(), result, resultCount );
            else
                _handler.accept( ipOutcome.notOk( ipso.msg(), ipso.cause() ) );
        };
        Consumer<Outcome<List<Inet6Address>>> handler6 = (ipso) -> {
            if( ipso.ok() )
                handleIPResults( _handler, ipso.info(), result, resultCount );
            else
                _handler.accept( ipOutcome.notOk( ipso.msg(), ipso.cause() ) );
        };

        // launch our two queries...
        Outcome<?> v4qo = resolveIPv4Addresses( handler4, _fqdn );
        Outcome<?> v6qo = resolveIPv6Addresses( handler6, _fqdn );

        // if both queries were ok, then report ok; otherwise, report the badness...
        return (v4qo.ok() && v6qo.ok())
                ? outcome.ok()
                : v4qo.ok()
                    ? outcome.notOk( v6qo.msg(), v6qo.cause() )
                    : outcome.notOk( v4qo.msg(), v4qo.cause() );
    }


    private synchronized void handleIPResults( final Consumer<Outcome<List<InetAddress>>> _handler, final List<? extends InetAddress> _received,
                                               final List<InetAddress> _result, final AtomicInteger _resultCount ) {
        _result.addAll( _received );
        int resultCount = _resultCount.incrementAndGet();
        if( resultCount == 2 ) {
            _handler.accept( ipOutcome.ok( _result ) );
        }
    }


    /**
     * <p>Asynchronously resolve the text records (TXT) for the given fully-qualified domain name (FQDN), calling the given handler with the result.</p>
     * <p>Returns a "not ok" outcome if there was a problem initiating network operations to transmit the query to a DNS server.</p>
     * <p>Note that it is possible for the handler to be called with the results in the caller's thread, before this method returns.  This is especially the case for any query
     * that was resolved from the resolver's cache.  The outcome argument to the handler will be "not ok" if there was a problem querying other DNS servers, or if the FQDN does
     * not exist.  Otherwise, it will be "ok", and the information will be a list of zero or more strings.</p>
     *
     * @param _handler  The {@link Consumer Consumer&lt;Outcome&lt;List&lt;String&gt;&gt;&gt;} handler that will be called with the result of this query.
     * @param _fqdn The FQDN (such as "www.google.com") to resolve into one or more IPv4 addresses.
     * @return The {@link Outcome Outcome&lt;?&gt;} that is "not ok" only if there was a problem initiating the query.
     */
    public Outcome<?> resolveText( final Consumer<Outcome<List<String>>> _handler, final String _fqdn  ) {

        Checks.required( _fqdn, _handler );

        // set up the handler that will process the raw results of the query...
        AsyncHandler<List<String>> handler = new AsyncHandler<>( _handler, (qr) -> extractText( qr.response().answers ) );

        // get the question we're going to ask the DNS...
        Outcome<DNSQuestion> qo = DNSUtil.getQuestion( _fqdn, DNSRRType.TXT );
        if( qo.notOk() ) return outcome.notOk( qo.msg(), qo.cause() );

        // fire off the query...
        return query( qo.info(), handler::handler );
    }


    /**
     * <p>Asynchronously resolve the domain names of the name servers for the given fully-qualified domain name (FQDN), calling the given handler with the result.</p>
     * <p>Returns a "not ok" outcome if there was a problem initiating network operations to transmit the query to a DNS server.</p>
     * <p>Note that it is possible for the handler to be called with the results in the caller's thread, before this method returns.  This is especially the case for any query
     * that was resolved from the resolver's cache.  The outcome argument to the handler will be "not ok" if there was a problem querying other DNS servers, or if the FQDN does
     * not exist.  Otherwise, it will be "ok", and the information will be a list of zero or more strings.</p>
     *
     * @param _handler  The {@link Consumer Consumer&lt;Outcome&lt;List&lt;String&gt;&gt;&gt;} handler that will be called with the result of this query.
     * @param _fqdn The FQDN (such as "www.google.com") to resolve into one or more IPv4 addresses.
     * @return The {@link Outcome Outcome&lt;?&gt;} that is "not ok" only if there was a problem initiating the query.
     */
    public Outcome<?> resolveNameServers( final Consumer<Outcome<List<String>>> _handler, final String _fqdn  ) {

        Checks.required( _fqdn, _handler );

        // set up the handler that will process the raw results of the query...
        AsyncHandler<List<String>> handler = new AsyncHandler<>( _handler, (qr) -> extractNameServers( qr.response().answers ) );

        // get the question we're going to ask the DNS...
        Outcome<DNSQuestion> qo = DNSUtil.getQuestion( _fqdn, DNSRRType.NS );
        if( qo.notOk() ) return outcome.notOk( qo.msg(), qo.cause() );

        // fire off the query...
        return query( qo.info(), handler::handler );
    }


    /**
     * <p>Synchronously resolve the {@link DNSResourceRecord}s of the given {@link DNSRRType} for the given fully-qualified domain name (FQDN), returning an
     * {@link Outcome Outcome&lt;List&lt;DNSResourceRecord&gt;&gtl;} with the result.  Note that the type may be
     * {@link DNSRRType#ANY}, which will cause <i>all</i> resource records for the given FQDN to be resolved.</p>
     * <p>Returns a "not ok" outcome for any problem occurring during this operation.</p>
     * <p>Note that it is possible for the handler to be called with the results in the caller's thread, before this method returns.  This is especially the case for any query
     * that was resolved from the resolver's cache.  The outcome argument to the handler will be "not ok" if there was a problem querying other DNS servers, or if the FQDN does
     * not exist.  Otherwise, it will be "ok", and the information will be a list of zero or more {@link DNSResourceRecord}s.</p>
     *
     * @param _fqdn The FQDN (such as "www.google.com") to resolve into zero or more DNS resource records.
     * @param _type The {@link DNSRRType} of resource records to resolve.
     * @return The {@link Outcome Outcome&lt;List&lt;DNSResourceRecord&gt;&gtl;} result.
     */
    public Outcome<List<DNSResourceRecord>> resolve( final String _fqdn, final DNSRRType _type ) {

        Checks.required( _fqdn, _type );

        // set up the handler that will process wait for the asynchronous result...
        SyncHandler<List<DNSResourceRecord>> handler = new SyncHandler<>();

        // initiate an asynchronous query...
        Outcome<?> ao = resolve( handler::handler, _fqdn, _type );

        // if we had a problem sending the query, fail politely...
        if( ao.notOk() )
            return handler.syncOutcome.notOk( ao.msg(), ao.cause() );

        // now we just wait for our answer to arrive...
        return handler.waitForCompletion();
    }


    /**
     * Synchronously resolve the Internet Protocol version 4 (IPv4) addresses for the given fully-qualified domain name (FQDN), returning an
     * {@link Outcome Outcome&lt;List&lt;Inet4Address&gt;&gt;} with the result.  The outcome will be "not ok" if there was a problem querying other DNS servers, or if the FQDN
     * does not exist.  Otherwise, it will be "ok", and the information will be a list of zero or more IPv4 addresses.
     *
     * @param _fqdn The FQDN (such as "www.google.com") to resolve into zero or more IPv4 addresses.
     * @return The {@link Outcome Outcome&lt;List&lt;Inet4Address&gt;&gt;} with the result of this query.
     */
    public Outcome<List<Inet4Address>> resolveIPv4Addresses( final String _fqdn ) {

        Checks.required( _fqdn );

        // set up the handler that will process wait for the asynchronous result...
        SyncHandler<List<Inet4Address>> handler = new SyncHandler<>();

        // initiate an asynchronous query...
        Outcome<?> ao = resolveIPv4Addresses( handler::handler, _fqdn );

        // if we had a problem sending the query, fail politely...
        if( ao.notOk() )
            return handler.syncOutcome.notOk( ao.msg(), ao.cause() );

        // now we just wait for our answer to arrive...
        return handler.waitForCompletion();
    }


    /**
     * Synchronously resolve the Internet Protocol version 6 (IPv6) addresses for the given fully-qualified domain name (FQDN), returning an
     * {@link Outcome Outcome&lt;List&lt;Inet6Address&gt;&gt;} with the result.  The outcome will be "not ok" if there was a problem querying other DNS servers, or if the FQDN
     * does not exist.  Otherwise, it will be "ok", and the information will be a list of zero or more IPv6 addresses.
     *
     * @param _fqdn The FQDN (such as "www.google.com") to resolve into zero or more IPv6 addresses.
     * @return The {@link Outcome Outcome&lt;List&lt;Inet6Address&gt;&gt;} with the result of this query.
     */
    public Outcome<List<Inet6Address>> resolveIPv6Addresses( final String _fqdn ) {

        Checks.required( _fqdn );

        // set up the handler that will process wait for the asynchronous result...
        SyncHandler<List<Inet6Address>> handler = new SyncHandler<>();

        // initiate an asynchronous query...
        Outcome<?> ao = resolveIPv6Addresses( handler::handler, _fqdn );

        // if we had a problem sending the query, fail politely...
        if( ao.notOk() )
            return handler.syncOutcome.notOk( ao.msg(), ao.cause() );

        // now we just wait for our answer to arrive...
        return handler.waitForCompletion();
    }


    /**
     * <p>Synchronously resolve the Internet Protocol addresses (both version 4 and 6) for the given fully-qualified domain name (FQDN), calling the given handler with the
     * result.  Note that this operation requires two queries.</p>
     * <p>Returns a "not ok" outcome if there was a problem initiating network operations to transmit either query to a DNS server.</p>
     * <p>Note that it is possible for the handler to be called with the results in the caller's thread, before this method returns.  This is especially the case for any query
     * that was resolved from the resolver's cache.  The outcome argument to the handler will be "not ok" if there was a problem querying other DNS servers, or if the FQDN does
     * not exist.  Otherwise, it will be "ok", and the information will be a list of zero or more IP addresses.</p>
    *
     * @param _fqdn The FQDN (such as "www.google.com") to resolve into zero or more IPv6 addresses.
     * @return The {@link Outcome Outcome&lt;List&lt;InetAddress&gt;&gt;} with the result of this query.
     */
    public Outcome<List<InetAddress>> resolveIPAddresses( final String _fqdn ) {

        Checks.required( _fqdn );

        // set up the handler that will process wait for the asynchronous result...
        SyncHandler<List<InetAddress>> handler = new SyncHandler<>();

        // initiate an asynchronous query...
        Outcome<?> ao = resolveIPAddresses( handler::handler, _fqdn );

        // if we had a problem sending the query, fail politely...
        if( ao.notOk() )
            return handler.syncOutcome.notOk( ao.msg(), ao.cause() );

        // now we just wait for our answer to arrive...
        return handler.waitForCompletion();
    }


    /**
     * Synchronously resolve the strings in TXT records for the given fully-qualified domain name (FQDN), returning an
     * {@link Outcome Outcome&lt;List&lt;String&gt;&gt;} with the result.  The outcome will be "not ok" if there was a problem querying other DNS servers, or if the FQDN
     * does not exist.  Otherwise, it will be "ok", and the information will be a list of zero or more strings.
     *
     * @param _fqdn The FQDN (such as "www.google.com") to resolve into one or more IPv4 addresses.
     * @return The {@link Outcome Outcome&lt;List&lt;String&gt;&gt;} with the result of this query.
     */
    public Outcome<List<String>> resolveText( final String _fqdn ) {

        Checks.required( _fqdn );

        // set up the handler that will process wait for the asynchronous result...
        SyncHandler<List<String>> handler = new SyncHandler<>();

        // initiate an asynchronous query...
        Outcome<?> ao = resolveText( handler::handler, _fqdn );

        // if we had a problem sending the query, fail politely...
        if( ao.notOk() )
            return handler.syncOutcome.notOk( ao.msg(), ao.cause() );

        // now we just wait for our answer to arrive...
        return handler.waitForCompletion();
    }


    /**
     * Synchronously resolve the domain names of the name servers for the given fully-qualified domain name (FQDN), returning an
     * {@link Outcome Outcome&lt;List&lt;String&gt;&gt;} with the result.  The outcome will be "not ok" if there was a problem querying other DNS servers, or if the FQDN
     * does not exist.  Otherwise, it will be "ok", and the information will be a list of zero or more strings.
     *
     * @param _fqdn The FQDN (such as "www.google.com") to resolve into one or more IPv4 addresses.
     * @return The {@link Outcome Outcome&lt;List&lt;String&gt;&gt;} with the result of this query.
     */
    public Outcome<List<String>> resolveNameServers( final String _fqdn ) {

        Checks.required( _fqdn );

        // set up the handler that will process wait for the asynchronous result...
        SyncHandler<List<String>> handler = new SyncHandler<>();

        // initiate an asynchronous query...
        Outcome<?> ao = resolveNameServers( handler::handler, _fqdn );

        // if we had a problem sending the query, fail politely...
        if( ao.notOk() )
            return handler.syncOutcome.notOk( ao.msg(), ao.cause() );

        // now we just wait for our answer to arrive...
        return handler.waitForCompletion();
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
     *  Helper class that accepts the result of an asynchronous query, processes the result into an outcome of the desired type, and calls the API user's handler.
     */
    private static class AsyncHandler<T> {

        private final Outcome.Forge<T>        asyncOutcome = new Outcome.Forge<>();
        private final Consumer<Outcome<T>>    handler;  // the handler supplied by the API user for a particular method...
        private final Function<QueryResult,T> munger;   // the function that processes the answers into the desired type...


        /**
         * Creates a new instance of this class with the given handler and munger.
         *
         * @param _handler The handler supplied by the API user for a particular method.
         * @param _munger The function that processes the answers into the desired type.
         */
        private AsyncHandler( final Consumer<Outcome<T>> _handler, final Function<QueryResult,T> _munger ) {
            handler = _handler;
            munger  = _munger;
        }


        /**
         * The handler for the result of a call to one of the {@link DNSResolver} query methods.
         *
         * @param _qr The result of a call to one of the {@link DNSResolver} query methods.
         */
        private void handler( final Outcome<QueryResult> _qr ) {

            // we're sending the result back as an {@link Outcome} of the desired type...
            handler.accept(
                    _qr.ok()                                                 // how we build the outcome depends on whether it was ok...
                            ? asyncOutcome.ok( munger.apply( _qr.info() ) )  // it was ok, so munge the QueryResult to get the type we want...
                            : asyncOutcome.notOk( _qr.msg(), _qr.cause() )   // it was not ok, so just relay the message and cause...
            );
        }
    }


    /**
     * Helper class that provides a semaphore for the user's thread to block on until the query has completed, accepts the result of an asynchronous query, then processes the
     * result into an outcome of the desired type and passes that to the user's thread when it resumes.
     */
    private static class SyncHandler<T> {

        private final Outcome.Forge<T>        syncOutcome = new Outcome.Forge<>();
        private final Semaphore               waiter = new Semaphore( 0 );
        private       Outcome<T>              asyncOutcome;


        private void handler( final Outcome<T> _asyncOutcome ) {
            asyncOutcome = _asyncOutcome;
            waiter.release();
        }

        private Outcome<T> waitForCompletion() {

            try {
                waiter.acquire();
            } catch( InterruptedException _e ) {
                // naught to do...
            }

            return asyncOutcome.ok()                                                   // how we build the outcome depends on whether it was ok...
                    ? syncOutcome.ok(    asyncOutcome.info()                      )    // it was ok, so the asyncOutcome has our data...
                    : syncOutcome.notOk( asyncOutcome.msg(), asyncOutcome.cause() );   // it was not ok, so just relay the message and cause...
        }
    }
}
