package com.dilatush.dns;

import com.dilatush.dns.message.DNSQuestion;
import com.dilatush.dns.message.DNSRRType;
import com.dilatush.dns.misc.DNSServerSelection;
import com.dilatush.dns.misc.DNSUtil;
import com.dilatush.dns.query.DNSTransport;
import com.dilatush.dns.rr.DNSResourceRecord;
import com.dilatush.util.Checks;
import com.dilatush.util.General;
import com.dilatush.util.Outcome;
import com.dilatush.util.ip.IPAddress;
import com.dilatush.util.ip.IPv4Address;
import com.dilatush.util.ip.IPv6Address;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Semaphore;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.BiConsumer;
import java.util.function.Consumer;
import java.util.function.Function;
import java.util.logging.Logger;

import static com.dilatush.dns.misc.DNSUtil.*;
import static com.dilatush.dns.query.DNSQuery.QueryResult;
import static com.dilatush.dns.query.DNSTransport.UDP;

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
    private static final Outcome.Forge<List<IPAddress>>    ipOutcome   = new Outcome.Forge<>();

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
     * <p>Asynchronously resolve the {@link DNSResourceRecord}s of the given {@link DNSRRType} for the given fully-qualified domain name (FQDN).  The given handler will be
     * called with the result.  Note that the type may be {@link DNSRRType#ANY}, which will cause <i>all</i> resource records for the given FQDN to be resolved.</p>
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
        Checks.required( _handler );
        return resolveImpl( _handler, null, _fqdn, _type, null );
    }


    /**
     * <p>Asynchronously resolve the {@link DNSResourceRecord}s of the given {@link DNSRRType} for the given fully-qualified domain name (FQDN).  The given handler will be called
     * with the result.  Note that the type may be {@link DNSRRType#ANY}, which will cause <i>all</i> resource records for the given FQDN to be resolved.</p>
     * <p>The given attachment (which may be {@code null}) is not used in the resolving process, but is simply carried through to the handler when it is called.  While the
     * attachment can be used for any purpose, the intent is to provide a convenient way to link the query call with the call to the handler.  For this purpose the attachment
     * is generally either an identifier of some sort (an index, a key, etc.) or a reference to the object that needs to be acted upon with the result.</p>
     * <p>Returns a "not ok" outcome if there was a problem initiating network operations to transmit the query to a DNS server.</p>
     * <p>Note that it is possible for the handler to be called with the results in the caller's thread, before this method returns.  This is especially the case for any query
     * that was resolved from the resolver's cache.  The outcome argument to the handler will be "not ok" if there was a problem querying other DNS servers, or if the FQDN does
     * not exist.  Otherwise, it will be "ok", and the information will be a list of zero or more {@link DNSResourceRecord}s.</p>
     *
     * @param _handler  The {@link BiConsumer BiConsumer&lt;Outcome&lt;List&lt;DNSResourceRecord&gt;&gt;,Object&gt;} handler that will be called with the result of this query.
     * @param _fqdn The FQDN (such as "www.google.com") to resolve into zero or more DNS resource records.
     * @param _type The {@link DNSRRType} of resource records to resolve.
     * @return The {@link Outcome Outcome&lt;?&gt;} that is "not ok" only if there was a problem initiating the query.
     */
    public Outcome<?> resolve( final BiConsumer<Outcome<List<DNSResourceRecord>>,Object> _handler, final String _fqdn, final DNSRRType _type, final Object _attachment ) {
        Checks.required( _handler );
        return resolveImpl( null, _handler, _fqdn, _type, _attachment );
    }


    /**
     * <p>Internal implementation that asynchronously resolves the {@link DNSResourceRecord}s of the given {@link DNSRRType} for the given fully-qualified domain name (FQDN),
     * calling one of the given handlers with the result.  If handler1 is provided, it is used and no attachment will be provided to the handler.  Otherwise, handler2 will be
     * used and the given attachment will be provided to the handler.  At least one of the handlers <i>must</i> be provided.  Note that the type may be {@link DNSRRType#ANY},
     * which will cause <i>all</i> resource records for the given FQDN to be resolved.</p>
     * <p>Returns a "not ok" outcome if there was a problem initiating network operations to transmit the query to a DNS server.</p>
     * <p>Note that it is possible for the handler to be called with the results in the caller's thread, before this method returns.  This is especially the case for any query
     * that was resolved from the resolver's cache.  The outcome argument to the handler will be "not ok" if there was a problem querying other DNS servers, or if the FQDN does
     * not exist.  Otherwise, it will be "ok", and the information will be a list of zero or more {@link DNSResourceRecord}s.</p>
     *
     * @param _handler1 The {@link Consumer Consumer&lt;Outcome&lt;List&lt;DNSResourceRecord&gt;&gt;&gt;} handler that may be called with the result of this query.
     * @param _handler2  The {@link BiConsumer BiConsumer&lt;Outcome&lt;List&lt;DNSResourceRecord&gt;&gt;,Object&gt;} handler that may be called with the result of this query.
     * @param _fqdn The FQDN (such as "www.google.com") to resolve into zero or more DNS resource records.
     * @param _type The {@link DNSRRType} of resource records to resolve.
     * @return The {@link Outcome Outcome&lt;?&gt;} that is "not ok" only if there was a problem initiating the query.
     */
    private Outcome<?> resolveImpl( final Consumer<Outcome<List<DNSResourceRecord>>> _handler1, final BiConsumer<Outcome<List<DNSResourceRecord>>,Object> _handler2,
                                   final String _fqdn, final DNSRRType _type, final Object _attachment ) {

        Checks.required( _fqdn, _type );

        // set up the handler that will process the raw results of the query...
        AsyncHandler<List<DNSResourceRecord>> handler = (_handler1 != null)
                ? new AsyncHandler<>( _handler1, (qr) -> qr.response().answers              )
                : new AsyncHandler<>( _handler2, (qr) -> qr.response().answers, _attachment );

        // get the question we're going to ask the DNS...
        Outcome<DNSQuestion> qo = DNSUtil.getQuestion( _fqdn, _type );
        if( qo.notOk() ) return outcome.notOk( qo.msg(), qo.cause() );

        // fire off the query...
        return (_handler1 != null)
                ? query( qo.info(), handler::handler1              )
                : query( qo.info(), handler::handler2, _attachment );
    }


    /**
     * <p>Asynchronously resolve the Internet Protocol version 4 (IPv4) addresses for the given fully-qualified domain name (FQDN).  The given handler will be called
     * with the result.</p>
     * <p>Returns a "not ok" outcome if there was a problem initiating network operations to transmit the query to a DNS server.</p>
     * <p>Note that it is possible for the handler to be called with the results in the caller's thread, before this method returns.  This is especially the case for any query
     * that was resolved from the resolver's cache.  The outcome argument to the handler will be "not ok" if there was a problem querying other DNS servers, or if the FQDN does
     * not exist.  Otherwise, it will be "ok", and the information will be a list of zero or more IPv4 addresses.</p>
     *
     * @param _handler  The {@link Consumer Consumer&lt;Outcome&lt;List&lt;IPv4Address&gt;&gt;&gt;} handler that will be called with the result of this query.
     * @param _fqdn The FQDN (such as "www.google.com") to resolve into zero or more IPv4 addresses.
     * @return The {@link Outcome Outcome&lt;?&gt;} that is "not ok" only if there was a problem initiating the query.
     */
    public Outcome<?> resolveIPv4Addresses( final Consumer<Outcome<List<IPv4Address>>> _handler, final String _fqdn  ) {
        Checks.required( _handler );
        return resolveIPv4AddressesImpl( _handler, null, _fqdn, null );
    }


    /**
     * <p>Asynchronously resolve the Internet Protocol version 4 (IPv4) addresses for the given fully-qualified domain name (FQDN).  The given handler will be called
     * with the result.</p>
     * <p>The given attachment (which may be {@code null}) is not used in the resolving process, but is simply carried through to the handler when it is called.  While the
     * attachment can be used for any purpose, the intent is to provide a convenient way to link the query call with the call to the handler.  For this purpose the attachment
     * is generally either an identifier of some sort (an index, a key, etc.) or a reference to the object that needs to be acted upon with the result.</p>
     * <p>Returns a "not ok" outcome if there was a problem initiating network operations to transmit the query to a DNS server.</p>
     * <p>Note that it is possible for the handler to be called with the results in the caller's thread, before this method returns.  This is especially the case for any query
     * that was resolved from the resolver's cache.  The outcome argument to the handler will be "not ok" if there was a problem querying other DNS servers, or if the FQDN does
     * not exist.  Otherwise, it will be "ok", and the information will be a list of zero or more IPv4 addresses.</p>
     *
     * @param _handler  The {@link BiConsumer BiConsumer&lt;Outcome&lt;List&lt;IPv4Address&gt;&gt;,Object&gt;} handler that will be called with the result of this query.
     * @param _fqdn The FQDN (such as "www.google.com") to resolve into zero or more IPv4 addresses.
     * @param _attachment The attachment for the query.
     * @return The {@link Outcome Outcome&lt;?&gt;} that is "not ok" only if there was a problem initiating the query.
     */
    public Outcome<?> resolveIPv4Addresses( final BiConsumer<Outcome<List<IPv4Address>>,Object> _handler, final String _fqdn, final Object _attachment ) {
        Checks.required( _handler );
        return resolveIPv4AddressesImpl( null, _handler, _fqdn, _attachment );
    }


    /**
     * <p>Internal implementation that asynchronously resolves the Internet Protocol version 4 (IPv4) addresses for the given fully-qualified domain name (FQDN), calling
     * one of the given handlers with the result.  If handler1 is provided, it is used and no attachment will be provided to the handler.  Otherwise, handler2 will be used
     * and the given attachment will be provided to the handler.  At least one of the handlers <i>must</i> be provided.</p>
     * <p>Returns a "not ok" outcome if there was a problem initiating network operations to transmit the query to a DNS server.</p>
     * <p>Note that it is possible for the handler to be called with the results in the caller's thread, before this method returns.  This is especially the case for any query
     * that was resolved from the resolver's cache.  The outcome argument to the handler will be "not ok" if there was a problem querying other DNS servers, or if the FQDN does
     * not exist.  Otherwise, it will be "ok", and the information will be a list of zero or more IPv4 addresses.</p>
     *
     * @param _handler1  The {@link Consumer Consumer&lt;Outcome&lt;List&lt;IPv4Address&gt;&gt;&gt;} handler that may be called with the result of this query.
     * @param _handler2 The {@link BiConsumer BiConsumer&lt;Outcome&lt;List&lt;IPv4Address&gt;&gt;,Object&gt;} handler that may be called with the result of this query.
     * @param _fqdn The FQDN (such as "www.google.com") to resolve into zero or more IPv4 addresses.
     * @param _attachment The optional attachment, used if handler1 is {@code null} and handler2 is specified.
     * @return The {@link Outcome Outcome&lt;?&gt;} that is "not ok" only if there was a problem initiating the query.
     */
    private Outcome<?> resolveIPv4AddressesImpl( final Consumer<Outcome<List<IPv4Address>>> _handler1, final BiConsumer<Outcome<List<IPv4Address>>,Object> _handler2,
                                                 final String _fqdn, final Object _attachment ) {

        Checks.required( _fqdn );

        // set up the handler that will process the raw results of the query...
        AsyncHandler<List<IPv4Address>> handler = (_handler1 != null)
                ? new AsyncHandler<>( _handler1, (qr) -> extractIPv4Addresses( qr.response().answers )              )
                : new AsyncHandler<>( _handler2, (qr) -> extractIPv4Addresses( qr.response().answers ), _attachment );

        // get the question we're going to ask the DNS...
        Outcome<DNSQuestion> qo = DNSUtil.getQuestion( _fqdn, DNSRRType.A );
        if( qo.notOk() ) return outcome.notOk( qo.msg(), qo.cause() );

        // fire off the query...
        return (_handler1 != null)
                ? query( qo.info(), handler::handler1              )
                : query( qo.info(), handler::handler2, _attachment );
    }


    /**
     * <p>Asynchronously resolve the Internet Protocol version 6 (IPv6) addresses for the given fully-qualified domain name (FQDN).  The given handler will be called
     * with the result.</p>
     * <p>Returns a "not ok" outcome if there was a problem initiating network operations to transmit the query to a DNS server.</p>
     * <p>Note that it is possible for the handler to be called with the results in the caller's thread, before this method returns.  This is especially the case for any query
     * that was resolved from the resolver's cache.  The outcome argument to the handler will be "not ok" if there was a problem querying other DNS servers, or if the FQDN does
     * not exist.  Otherwise, it will be "ok", and the information will be a list of zero or more IPv6 addresses.</p>
     *
     * @param _handler  The {@link Consumer Consumer&lt;Outcome&lt;List&lt;IPv6Address&gt;&gt;&gt;} handler that will be called with the result of this query.
     * @param _fqdn The FQDN (such as "www.google.com") to resolve into zero or more IPv6 addresses.
     * @return The {@link Outcome Outcome&lt;?&gt;} that is "not ok" only if there was a problem initiating the query.
     */
    public Outcome<?> resolveIPv6Addresses( final Consumer<Outcome<List<IPv6Address>>> _handler, final String _fqdn  ) {
        Checks.required( _handler );
        return resolveIPv6AddressesImpl( _handler, null, _fqdn, null );
    }


    /**
     * <p>Asynchronously resolve the Internet Protocol version 6 (IPv6) addresses for the given fully-qualified domain name (FQDN).  The given handler will be called
     * with the result.</p>
     * <p>The given attachment (which may be {@code null}) is not used in the resolving process, but is simply carried through to the handler when it is called.  While the
     * attachment can be used for any purpose, the intent is to provide a convenient way to link the query call with the call to the handler.  For this purpose the attachment
     * is generally either an identifier of some sort (an index, a key, etc.) or a reference to the object that needs to be acted upon with the result.</p>
     * <p>Returns a "not ok" outcome if there was a problem initiating network operations to transmit the query to a DNS server.</p>
     * <p>Note that it is possible for the handler to be called with the results in the caller's thread, before this method returns.  This is especially the case for any query
     * that was resolved from the resolver's cache.  The outcome argument to the handler will be "not ok" if there was a problem querying other DNS servers, or if the FQDN does
     * not exist.  Otherwise, it will be "ok", and the information will be a list of zero or more IPv6 addresses.</p>
     *
     * @param _handler  The {@link BiConsumer BiConsumer&lt;Outcome&lt;List&lt;IPv6Address&gt;&gt;,Object&gt;} handler that will be called with the result of this query.
     * @param _fqdn The FQDN (such as "www.google.com") to resolve into zero or more IPv6 addresses.
     * @param _attachment The attachment for the query.
     * @return The {@link Outcome Outcome&lt;?&gt;} that is "not ok" only if there was a problem initiating the query.
     */
    public Outcome<?> resolveIPv6Addresses( final BiConsumer<Outcome<List<IPv6Address>>,Object> _handler, final String _fqdn, final Object _attachment ) {
        Checks.required( _handler );
        return resolveIPv6AddressesImpl( null, _handler, _fqdn, _attachment );
    }


    /**
     * <p>Internal implementation that asynchronously resolves the Internet Protocol version 6 (IPv6) addresses for the given fully-qualified domain name (FQDN), calling
     * one of the given handlers with the result.  If handler1 is provided, it is used and no attachment will be provided to the handler.  Otherwise, handler2 will be used
     * and the given attachment will be provided to the handler.  At least one of the handlers <i>must</i> be provided.</p>
     * <p>Returns a "not ok" outcome if there was a problem initiating network operations to transmit the query to a DNS server.</p>
     * <p>Note that it is possible for the handler to be called with the results in the caller's thread, before this method returns.  This is especially the case for any query
     * that was resolved from the resolver's cache.  The outcome argument to the handler will be "not ok" if there was a problem querying other DNS servers, or if the FQDN does
     * not exist.  Otherwise, it will be "ok", and the information will be a list of zero or more IPv6 addresses.</p>
     *
     * @param _handler1  The {@link Consumer Consumer&lt;Outcome&lt;List&lt;IPv6Address&gt;&gt;&gt;} handler that may be called with the result of this query.
     * @param _handler2  The {@link Consumer BiConsumer&lt;Outcome&lt;List&lt;IPv6Address&gt;&gt;,Object&gt;} handler that may be called with the result of this query.
     * @param _fqdn The FQDN (such as "www.google.com") to resolve into zero or more IPv6 addresses.
     * @param _attachment The attachment for the query.
     * @return The {@link Outcome Outcome&lt;?&gt;} that is "not ok" only if there was a problem initiating the query.
     */
    private Outcome<?> resolveIPv6AddressesImpl( final Consumer<Outcome<List<IPv6Address>>> _handler1, final BiConsumer<Outcome<List<IPv6Address>>,Object> _handler2,
                                                 final String _fqdn, final Object _attachment  ) {

        Checks.required( _fqdn );

        // set up the handler that will process the raw results of the query...
        AsyncHandler<List<IPv6Address>> handler = (_handler1 != null)
                ? new AsyncHandler<>( _handler1, (qr) -> extractIPv6Addresses( qr.response().answers )              )
                : new AsyncHandler<>( _handler2, (qr) -> extractIPv6Addresses( qr.response().answers ), _attachment );

        // get the question we're going to ask the DNS...
        Outcome<DNSQuestion> qo = DNSUtil.getQuestion( _fqdn, DNSRRType.AAAA );
        if( qo.notOk() ) return outcome.notOk( qo.msg(), qo.cause() );

        // fire off the query...
        return (_handler1 != null)
                ? query( qo.info(), handler::handler1              )
                : query( qo.info(), handler::handler2, _attachment );
    }


    /**
     * <p>Asynchronously resolve the Internet Protocol addresses (both version 4 and 6) for the given fully-qualified domain name (FQDN).  The given handler will be called
     * with the result.  Note that this operation results in two DNS queries, as it is only possible to query for each address type separately.</p>
     * <p>Returns a "not ok" outcome if there was a problem initiating network operations to transmit either query to a DNS server.</p>
     * <p>Note that it is possible for the handler to be called with the results in the caller's thread, before this method returns.  This is especially the case for any query
     * that was resolved from the resolver's cache.  The outcome argument to the handler will be "not ok" if there was a problem querying other DNS servers, or if the FQDN does
     * not exist.  Otherwise, it will be "ok", and the information will be a list of zero or more IP addresses.</p>
     *
     * @param _handler  The {@link Consumer Consumer&lt;Outcome&lt;List&lt;IPv6Address&gt;&gt;&gt;} handler that will be called with the result of this query.
     * @param _fqdn The FQDN (such as "www.google.com") to resolve into zero or more IP addresses.
     * @return The {@link Outcome Outcome&lt;?&gt;} that is "not ok" only if there was a problem initiating the query.
     */
    public Outcome<?> resolveIPAddresses( final Consumer<Outcome<List<IPAddress>>> _handler, final String _fqdn  ) {
        Checks.required( _handler );
        return resolveIPAddressesImpl( _handler, null, _fqdn, null );
    }


    /**
     * <p>Asynchronously resolve the Internet Protocol addresses (both version 4 and 6) for the given fully-qualified domain name (FQDN).  The given handler will be called
     * with the result.  Note that this operation results in two DNS queries, as it is only possible to query for each address type separately.</p>
     * <p>The given attachment (which may be {@code null}) is not used in the resolving process, but is simply carried through to the handler when it is called.  While the
     * attachment can be used for any purpose, the intent is to provide a convenient way to link the query call with the call to the handler.  For this purpose the attachment
     * is generally either an identifier of some sort (an index, a key, etc.) or a reference to the object that needs to be acted upon with the result.</p>
     * <p>Returns a "not ok" outcome if there was a problem initiating network operations to transmit either query to a DNS server.</p>
     * <p>Note that it is possible for the handler to be called with the results in the caller's thread, before this method returns.  This is especially the case for any query
     * that was resolved from the resolver's cache.  The outcome argument to the handler will be "not ok" if there was a problem querying other DNS servers, or if the FQDN does
     * not exist.  Otherwise, it will be "ok", and the information will be a list of zero or more IP addresses.</p>
     *
     * @param _handler  The {@link BiConsumer BiConsumer&lt;Outcome&lt;List&lt;IPv6Address&gt;&gt;,Object&gt;} handler that will be called with the result of this query.
     * @param _fqdn The FQDN (such as "www.google.com") to resolve into zero or more IP addresses.
     * @return The {@link Outcome Outcome&lt;?&gt;} that is "not ok" only if there was a problem initiating the query.
     */
    public Outcome<?> resolveIPAddresses( final BiConsumer<Outcome<List<IPAddress>>,Object> _handler, final String _fqdn, final Object _attachment ) {
        Checks.required( _handler );
        return resolveIPAddressesImpl( null, _handler, _fqdn, _attachment );
    }


    /**
     * <p>Internal implementation that asynchronously resolves the Internet Protocol addresses (both version 4 and 6) for the given fully-qualified domain name (FQDN), calling
     * one of the given handlers with the result.  If handler1 is provided, it is used and no attachment will be provided to the handler.  Otherwise, handler2 will be used
     * and the given attachment will be provided to the handler.  At least one of the handlers <i>must</i> be provided.  Note that this operation results in two DNS queries,
     * as it is only possible to query for each address type separately.</p>
     * <p>Returns a "not ok" outcome if there was a problem initiating network operations to transmit either query to a DNS server.</p>
     * <p>Note that it is possible for the handler to be called with the results in the caller's thread, before this method returns.  This is especially the case for any query
     * that was resolved from the resolver's cache.  The outcome argument to the handler will be "not ok" if there was a problem querying other DNS servers, or if the FQDN does
     * not exist.  Otherwise, it will be "ok", and the information will be a list of zero or more IP addresses.</p>
     *
     * @param _handler1  The {@link Consumer Consumer&lt;Outcome&lt;List&lt;IPv6Address&gt;&gt;&gt;} handler that will be called with the result of this query.
     * @param _handler2  The {@link BiConsumer BiConsumer&lt;Outcome&lt;List&lt;IPv6Address&gt;&gt;,Object&gt;} handler that will be called with the result of this query.
     * @param _fqdn The FQDN (such as "www.google.com") to resolve into zero or more IP addresses.
     * @param _attachment The attachment for the query.
     * @return The {@link Outcome Outcome&lt;?&gt;} that is "not ok" only if there was a problem initiating the query.
     */
    private Outcome<?> resolveIPAddressesImpl( final Consumer<Outcome<List<IPAddress>>> _handler1, final BiConsumer<Outcome<List<IPAddress>>,Object> _handler2,
                                               final String _fqdn, final Object _attachment ) {

        Checks.required( _fqdn );

        // where we're going to stuff the results...
        List<IPAddress> result = new ArrayList<>();

        // where we keep track of whether we've already received one result...
        AtomicInteger resultCount = new AtomicInteger();

        // We must make two separate queries to get the answers, as DNS can't query for both A and AAAA at once.  We're doing this asynchronously, so we make
        // both queries at once, then wait until we get two answers.  We return with an error if either query had errors being sent...

        // create our special handlers, to receive both IPv4 and IPv6 results...
        Consumer<Outcome<List<IPv4Address>>> handler4 = (ipso) -> {
            if( ipso.ok() )
                handleIPResults( _handler1, _handler2, ipso.info(), _attachment, result, resultCount );
            else if( _handler1 != null )
                _handler1.accept( ipOutcome.notOk( ipso.msg(), ipso.cause() ) );
            else
                _handler2.accept( ipOutcome.notOk( ipso.msg(), ipso.cause() ), _attachment );
        };
        Consumer<Outcome<List<IPv6Address>>> handler6 = (ipso) -> {
            if( ipso.ok() )
                handleIPResults( _handler1, _handler2, ipso.info(), _attachment, result, resultCount );
            else if( _handler1 != null )
                _handler1.accept( ipOutcome.notOk( ipso.msg(), ipso.cause() ) );
            else
                _handler2.accept( ipOutcome.notOk( ipso.msg(), ipso.cause() ), _attachment );
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


    private synchronized void handleIPResults( final Consumer<Outcome<List<IPAddress>>> _handler1, final BiConsumer<Outcome<List<IPAddress>>,Object> _handler2,
                                               final List<? extends IPAddress> _received, final Object _attachment,
                                               final List<IPAddress> _result, final AtomicInteger _resultCount ) {
        _result.addAll( _received );
        int resultCount = _resultCount.incrementAndGet();
        if( resultCount == 2 ) {
            if( _handler1 != null )
                _handler1.accept( ipOutcome.ok( _result ) );
            else
                _handler2.accept( ipOutcome.ok( _result ), _attachment );
        }
    }


    /**
     * <p>Asynchronously resolve the text records (TXT) for the given fully-qualified domain name (FQDN).  The given handler will be called with the result.</p>
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
        Checks.required( _handler );
        return resolveTextImpl( _handler, null, _fqdn, null );
    }


    /**
     * <p>Asynchronously resolve the text records (TXT) for the given fully-qualified domain name (FQDN).  The given handler will be called with the result.</p>
     * <p>The given attachment (which may be {@code null}) is not used in the resolving process, but is simply carried through to the handler when it is called.  While the
     * attachment can be used for any purpose, the intent is to provide a convenient way to link the query call with the call to the handler.  For this purpose the attachment
     * is generally either an identifier of some sort (an index, a key, etc.) or a reference to the object that needs to be acted upon with the result.</p>
     * <p>Returns a "not ok" outcome if there was a problem initiating network operations to transmit the query to a DNS server.</p>
     * <p>Note that it is possible for the handler to be called with the results in the caller's thread, before this method returns.  This is especially the case for any query
     * that was resolved from the resolver's cache.  The outcome argument to the handler will be "not ok" if there was a problem querying other DNS servers, or if the FQDN does
     * not exist.  Otherwise, it will be "ok", and the information will be a list of zero or more strings.</p>
     *
     * @param _handler  The {@link BiConsumer Consumer&lt;Outcome&lt;List&lt;String&gt;&gt;,Object&gt;} handler that will be called with the result of this query.
     * @param _fqdn The FQDN (such as "www.google.com") to resolve into one or more IPv4 addresses.
     * @return The {@link Outcome Outcome&lt;?&gt;} that is "not ok" only if there was a problem initiating the query.
     */
    public Outcome<?> resolveText( final BiConsumer<Outcome<List<String>>,Object> _handler, final String _fqdn, final Object _attachment ) {
        Checks.required( _handler );
        return resolveTextImpl( null, _handler, _fqdn, _attachment );
    }


    /**
     * <p>Internal implementation that asynchronously resolves the text records (TXT) for the given fully-qualified domain name (FQDN), calling
     * one of the given handlers with the result.  If handler1 is provided, it is used and no attachment will be provided to the handler.  Otherwise, handler2 will be used
     * and the given attachment will be provided to the handler.  At least one of the handlers <i>must</i> be provided.</p>
     * <p>Returns a "not ok" outcome if there was a problem initiating network operations to transmit the query to a DNS server.</p>
     * <p>Note that it is possible for the handler to be called with the results in the caller's thread, before this method returns.  This is especially the case for any query
     * that was resolved from the resolver's cache.  The outcome argument to the handler will be "not ok" if there was a problem querying other DNS servers, or if the FQDN does
     * not exist.  Otherwise, it will be "ok", and the information will be a list of zero or more strings.</p>
     *
     * @param _handler1  The {@link Consumer Consumer&lt;Outcome&lt;List&lt;String&gt;&gt;&gt;} handler that may be called with the result of this query.
     * @param _handler2  The {@link BiConsumer Consumer&lt;Outcome&lt;List&lt;String&gt;&gt;,Object&gt;} handler that may be called with the result of this query.
     * @param _fqdn The FQDN (such as "www.google.com") to resolve into one or more IPv4 addresses.
     * @param _attachment The attachment for the query.
     * @return The {@link Outcome Outcome&lt;?&gt;} that is "not ok" only if there was a problem initiating the query.
     */
    private Outcome<?> resolveTextImpl( final Consumer<Outcome<List<String>>> _handler1, final BiConsumer<Outcome<List<String>>,Object> _handler2,
                                        final String _fqdn, final Object _attachment ) {

        Checks.required( _fqdn );

        // set up the handler that will process the raw results of the query...
        AsyncHandler<List<String>> handler = (_handler1 != null)
                ? new AsyncHandler<>( _handler1, (qr) -> extractText( qr.response().answers )              )
                : new AsyncHandler<>( _handler2, (qr) -> extractText( qr.response().answers ), _attachment );

        // get the question we're going to ask the DNS...
        Outcome<DNSQuestion> qo = DNSUtil.getQuestion( _fqdn, DNSRRType.TXT );
        if( qo.notOk() ) return outcome.notOk( qo.msg(), qo.cause() );

        // fire off the query...
        return (_handler1 != null)
                ? query( qo.info(), handler::handler1              )
                : query( qo.info(), handler::handler2, _attachment );
    }


    /**
     * <p>Asynchronously resolve the domain names of the name servers for the given fully-qualified domain name (FQDN).  The given handler will be called with the result.</p>
     * <p>Returns a "not ok" outcome if there was a problem initiating network operations to transmit the query to a DNS server.</p>
     * <p>Note that it is possible for the handler to be called with the results in the caller's thread, before this method returns.  This is especially the case for any query
     * that was resolved from the resolver's cache.  The outcome argument to the handler will be "not ok" if there was a problem querying other DNS servers, or if the FQDN does
     * not exist.  Otherwise, it will be "ok", and the information will be a list of zero or more strings that are the FQDNs of name servers.</p>
     *
     * @param _handler  The {@link Consumer Consumer&lt;Outcome&lt;List&lt;String&gt;&gt;&gt;} handler that will be called with the result of this query.
     * @param _fqdn The FQDN (such as "www.google.com") to resolve into one or more IPv4 addresses.
     * @return The {@link Outcome Outcome&lt;?&gt;} that is "not ok" only if there was a problem initiating the query.
     */
    public Outcome<?> resolveNameServers( final Consumer<Outcome<List<String>>> _handler, final String _fqdn  ) {
        Checks.required( _handler );
        return resolveNameServersImpl( _handler, null, _fqdn, null );
    }


    /**
     * <p>Asynchronously resolve the domain names of the name servers for the given fully-qualified domain name (FQDN), calling the given handler with the result.</p>
     * <p>The given attachment (which may be {@code null}) is not used in the resolving process, but is simply carried through to the handler when it is called.  While the
     * attachment can be used for any purpose, the intent is to provide a convenient way to link the query call with the call to the handler.  For this purpose the attachment
     * is generally either an identifier of some sort (an index, a key, etc.) or a reference to the object that needs to be acted upon with the result.</p>
     * <p>Returns a "not ok" outcome if there was a problem initiating network operations to transmit the query to a DNS server.</p>
     * <p>Note that it is possible for the handler to be called with the results in the caller's thread, before this method returns.  This is especially the case for any query
     * that was resolved from the resolver's cache.  The outcome argument to the handler will be "not ok" if there was a problem querying other DNS servers, or if the FQDN does
     * not exist.  Otherwise, it will be "ok", and the information will be a list of zero or more strings that are the FQDNs of name servers.</p>
     *
     * @param _handler  The {@link BiConsumer Consumer&lt;Outcome&lt;List&lt;String&gt;&gt;,Object&gt;} handler that will be called with the result of this query.
     * @param _fqdn The FQDN (such as "www.google.com") to resolve into one or more IPv4 addresses.
     * @param _attachment The attachment for the query.
     * @return The {@link Outcome Outcome&lt;?&gt;} that is "not ok" only if there was a problem initiating the query.
     */
    public Outcome<?> resolveNameServers( final BiConsumer<Outcome<List<String>>,Object> _handler, final String _fqdn, final Object _attachment  ) {
        Checks.required( _handler );
        return resolveNameServersImpl( null, _handler, _fqdn, _attachment );
    }


    /**
     * <p>Internal implementation that asynchronously resolves the domain names of the name servers for the given fully-qualified domain name (FQDN).  One of the given
     * one of the given handlers with the result.  If handler1 is provided, it is used and no attachment will be provided to the handler.  Otherwise, handler2 will be used
     * and the given attachment will be provided to the handler.  At least one of the handlers <i>must</i> be provided.</p>
     * <p>Returns a "not ok" outcome if there was a problem initiating network operations to transmit the query to a DNS server.</p>
     * <p>Note that it is possible for the handler to be called with the results in the caller's thread, before this method returns.  This is especially the case for any query
     * that was resolved from the resolver's cache.  The outcome argument to the handler will be "not ok" if there was a problem querying other DNS servers, or if the FQDN does
     * not exist.  Otherwise, it will be "ok", and the information will be a list of zero or more strings that are the FQDNs of name servers.</p>
     *
     * @param _handler1  The {@link Consumer Consumer&lt;Outcome&lt;List&lt;String&gt;&gt;&gt;} handler that may be called with the result of this query.
     * @param _handler2  The {@link BiConsumer Consumer&lt;Outcome&lt;List&lt;String&gt;&gt;,Object&gt;} handler that may be called with the result of this query.
     * @param _fqdn The FQDN (such as "www.google.com") to resolve into one or more IPv4 addresses.
     * @param _attachment The attachment for this query.
     * @return The {@link Outcome Outcome&lt;?&gt;} that is "not ok" only if there was a problem initiating the query.
     */
    private Outcome<?> resolveNameServersImpl( final Consumer<Outcome<List<String>>> _handler1, final BiConsumer<Outcome<List<String>>,Object> _handler2,
                                               final String _fqdn, final Object _attachment  ) {

        Checks.required( _fqdn );

        // set up the handler that will process the raw results of the query...
        AsyncHandler<List<String>> handler = (_handler1 != null)
                ? new AsyncHandler<>( _handler1, (qr) -> extractNameServers( qr.response().answers )              )
                : new AsyncHandler<>( _handler2, (qr) -> extractNameServers( qr.response().answers ), _attachment );

        // get the question we're going to ask the DNS...
        Outcome<DNSQuestion> qo = DNSUtil.getQuestion( _fqdn, DNSRRType.NS );
        if( qo.notOk() ) return outcome.notOk( qo.msg(), qo.cause() );

        // fire off the query...
        return (_handler1 != null)
                ? query( qo.info(), handler::handler1              )
                : query( qo.info(), handler::handler2, _attachment );
    }


    /**
     * <p>Synchronously resolve the {@link DNSResourceRecord}s of the given {@link DNSRRType} for the given fully-qualified domain name (FQDN), returning an
     * {@link Outcome Outcome&lt;List&lt;DNSResourceRecord&gt;&gt;} with the result.  Note that the type may be
     * {@link DNSRRType#ANY}, which will cause <i>all</i> resource records for the given FQDN to be resolved.</p>
     * <p>Returns a "not ok" outcome for any problem occurring during this operation.</p>
     * <p>Note that it is possible for the handler to be called with the results in the caller's thread, before this method returns.  This is especially the case for any query
     * that was resolved from the resolver's cache.  The outcome argument to the handler will be "not ok" if there was a problem querying other DNS servers, or if the FQDN does
     * not exist.  Otherwise, it will be "ok", and the information will be a list of zero or more {@link DNSResourceRecord}s.</p>
     *
     * @param _fqdn The FQDN (such as "www.google.com") to resolve into zero or more DNS resource records.
     * @param _type The {@link DNSRRType} of resource records to resolve.
     * @return The {@link Outcome Outcome&lt;List&lt;DNSResourceRecord&gt;&gt;} result.
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
     * {@link Outcome Outcome&lt;List&lt;IPv4Address&gt;&gt;} with the result.  The outcome will be "not ok" if there was a problem querying other DNS servers, or if the FQDN
     * does not exist.  Otherwise, it will be "ok", and the information will be a list of zero or more IPv4 addresses.
     *
     * @param _fqdn The FQDN (such as "www.google.com") to resolve into zero or more IPv4 addresses.
     * @return The {@link Outcome Outcome&lt;List&lt;IPv4Address&gt;&gt;} with the result of this query.
     */
    public Outcome<List<IPv4Address>> resolveIPv4Addresses( final String _fqdn ) {

        Checks.required( _fqdn );

        // set up the handler that will process wait for the asynchronous result...
        SyncHandler<List<IPv4Address>> handler = new SyncHandler<>();

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
     * {@link Outcome Outcome&lt;List&lt;IPv6Address&gt;&gt;} with the result.  The outcome will be "not ok" if there was a problem querying other DNS servers, or if the FQDN
     * does not exist.  Otherwise, it will be "ok", and the information will be a list of zero or more IPv6 addresses.
     *
     * @param _fqdn The FQDN (such as "www.google.com") to resolve into zero or more IPv6 addresses.
     * @return The {@link Outcome Outcome&lt;List&lt;IPv6Address&gt;&gt;} with the result of this query.
     */
    public Outcome<List<IPv6Address>> resolveIPv6Addresses( final String _fqdn ) {

        Checks.required( _fqdn );

        // set up the handler that will process wait for the asynchronous result...
        SyncHandler<List<IPv6Address>> handler = new SyncHandler<>();

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
     * @return The {@link Outcome Outcome&lt;List&lt;IPAddress&gt;&gt;} with the result of this query.
     */
    public Outcome<List<IPAddress>> resolveIPAddresses( final String _fqdn ) {

        Checks.required( _fqdn );

        // set up the handler that will process wait for the asynchronous result...
        SyncHandler<List<IPAddress>> handler = new SyncHandler<>();

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
    private Outcome<?> query( final DNSQuestion _question, final BiConsumer<Outcome<QueryResult>,Object> _handler, final Object _attachment ) {

        // which query method we call on the resolver depends on whether we're forwarding or recursively resolving...
        if( resolver.hasServers() ) {

            // make the forwarding call...
            return resolver.query( _question, _handler, initialTransport, serverSelection );
        }
        else {

            // make the recursive call...
            return resolver.query( _question, _handler, initialTransport, _attachment );
        }
    }


    /**
     *  Helper class that accepts the result of an asynchronous query, processes the result into an outcome of the desired type, and calls the API user's handler.
     */
    private static class AsyncHandler<T> {

        private final Outcome.Forge<T>        asyncOutcome = new Outcome.Forge<>();
        private final Consumer<Outcome<T>>    handler1;  // the handler supplied by the API user for a particular method...
        private final BiConsumer<Outcome<T>,Object>    handler2;  // the handler supplied by the API user for a particular method...
        private final boolean                 useAttachment;
        private final Function<QueryResult,T> munger;   // the function that processes the answers into the desired type...


        /**
         * Creates a new instance of this class with the given handler and munger.
         *
         * @param _handler The handler supplied by the API user for a particular method.
         * @param _munger The function that processes the answers into the desired type.
         */
        private AsyncHandler( final Consumer<Outcome<T>> _handler, final Function<QueryResult,T> _munger ) {
            Checks.required( _handler );
            handler1 = _handler;
            handler2 = null;
            useAttachment = false;
            munger  = _munger;
        }


        /**
         * Creates a new instance of this class with the given handler and munger.
         *
         * @param _handler The handler supplied by the API user for a particular method.
         * @param _munger The function that processes the answers into the desired type.
         */
        private AsyncHandler( final BiConsumer<Outcome<T>,Object> _handler, final Function<QueryResult,T> _munger, final Object _attachment ) {
            Checks.required( _handler );
            handler1 = null;
            handler2 = _handler;
            useAttachment = true;
            munger  = _munger;
        }


        /**
         * The handler for the result of a call to one of the {@link DNSResolver} query methods.
         *
         * @param _qr The result of a call to one of the {@link DNSResolver} query methods.
         */
        private void handler1( final Outcome<QueryResult> _qr ) {

            // we're sending the result back as an {@link Outcome} of the desired type...
            handler1.accept(
                    _qr.ok()                                                 // how we build the outcome depends on whether it was ok...
                            ? asyncOutcome.ok( munger.apply( _qr.info() ) )  // it was ok, so munge the QueryResult to get the type we want...
                            : asyncOutcome.notOk( _qr.msg(), _qr.cause() )   // it was not ok, so just relay the message and cause...
            );
        }


        /**
         * The handler for the result of a call to one of the {@link DNSResolver} query methods.
         *
         * @param _qr The result of a call to one of the {@link DNSResolver} query methods.
         */
        private void handler2( final Outcome<QueryResult> _qr, final Object _attachment ) {

            // we're sending the result back as an {@link Outcome} of the desired type...
            handler2.accept(
                    _qr.ok()                                                 // how we build the outcome depends on whether it was ok...
                            ? asyncOutcome.ok( munger.apply( _qr.info() ) )  // it was ok, so munge the QueryResult to get the type we want...
                            : asyncOutcome.notOk( _qr.msg(), _qr.cause() )   // it was not ok, so just relay the message and cause...
                    , _attachment
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
