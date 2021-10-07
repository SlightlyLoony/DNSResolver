package com.dilatush.dns;

// TODO: Handle responses with no answers (see RFC 2308)
// TODO: make sure all "not ok" responses are using codes (DNSResponseCode or DNSResolverError)
// TODO: Get rid of protected everywhere I can
// TODO: Comments and Javadocs...


import com.dilatush.dns.misc.*;
import com.dilatush.dns.message.DNSMessage;
import com.dilatush.dns.message.DNSOpCode;
import com.dilatush.dns.message.DNSQuestion;
import com.dilatush.dns.message.DNSRRType;
import com.dilatush.dns.query.*;
import com.dilatush.dns.rr.DNSResourceRecord;
import com.dilatush.util.Checks;
import com.dilatush.util.ExecutorService;
import com.dilatush.util.Outcome;

import java.net.InetSocketAddress;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.BiConsumer;
import java.util.function.Consumer;
import java.util.logging.Logger;

import static com.dilatush.dns.misc.DNSIPVersion.*;
import static com.dilatush.dns.message.DNSRRType.*;
import static com.dilatush.dns.query.DNSQuery.QueryResult;
import static com.dilatush.util.General.getLogger;

/**
 * <p>Instances of this class implement a DNS "resolver".  Given a fully-qualified domain name (FQDN), a resolver uses name servers on the Internet to discover information about
 * that FQDN.  Most commonly the information sought is the IP address (v4 or v6) of the host with that FQDN, but there are other uses as well.  For instance, given the FQDN
 * "cnn.com", a resolver can discover the FQDNs of mail exchangers (servers) for that domain, or the name servers that are authoritative for that domain.</p>
 * <p>DNS resolvers can operate in one or both of two quite different modes: by forwarding a query to a recursive name server (forwarded mode) or by doing all the work itself
 * (recursive mode).
 * Most programmers are familiar with forwarded mode, as it's how most DNS resolvers on clients or servers work.  Generally the host has a DNS resolver built into the operating
 * system, and this resolver knows the IP addresses of one or more recursive name servers (such as Google's DNS service, OpenDNS, the ISP's DNS server, etc.).  In this most
 * common case, the host's DNS resolver is simply delegating the work to the recursive name server.  A DNS resolver operating in recursive mode does something much more complex,
 * and best illustrated with an example.  Suppose, for instance, that we want to resolve the IPv4 address for "www.bogus.com".  Here are the steps a DNS resolver operating in
 * recursive mode would go through:</p>
 * <ol>
 *     <li>Read the "root hints" file.  This has a list of the domain names and IP addresses for the root name servers.</li>
 *     <li>Query a root name server for "www.bogus.com".  It answers with the domain names (and perhaps IP addresses) for authoritative name servers for "com".  If the
 *     IP addresses were not supplied, query for them in a separate query.</li>
 *     <li>Query a "com" name server for "www.bogus.com".  It answers with the domain names (and perhaps IP addresses) for authoritative name servers for "bogus.com".  If
 *     the IP addresses were not supplied, query for them in a separate query.</li>
 *     <li>Query a "bogus.com" name server for "www.bogus.com".  It answers with the IPv4 address for "www.bogus.com".</li>
 * </ol>
 * <p>Note that this process can result in dozens of DNS servers on the Internet being queried for information in order to answer a <i>single</i> query made to the resolver.
 * This overhead is greatly reduced by using a cache (see below).</p>
 * <p>Instances of this class can operate in either forwarding mode or recursive mode; this option is selected for each query made.</p>
 * <p>Instances of this class include an optional cache of the results of DNS queries, which can greatly increase the resolver's performance when multiple queries to the same
 * domain are made.  This is a very common occurrence in almost any application, so using the cache is highly recommended.</p>
 */
@SuppressWarnings( "unused" )
public class DNSResolver {

    private static final Logger                     LOGGER             = getLogger();
    private static final Outcome.Forge<DNSResolver> outcomeResolver    = new Outcome.Forge<>();
    private static final Outcome.Forge<QueryResult> outcomeQueryResult = new Outcome.Forge<>();
    private static final Outcome.Forge<?>           outcome            = new Outcome.Forge<>();

    private final ExecutorService               executor;
    private final DNSNIO                        nio;
    private final DNSIPVersion                  ipVersion;
    private final List<ServerSpec>              serverSpecs;
    private final Map<String,ServerSpec>        serversByName;
    private final List<ServerSpec>              serversByPriority;
    private final List<ServerSpec>              serversBySpeed;
    private final Map<Short,DNSQuery>           activeQueries;
    private final AtomicInteger                 nextQueryID;
    private final DNSCache                      cache;
    private final DNSRootHints                  rootHints;


    /**
     * Creates a new instance of this class with the given parameters.
     *
     * @param _executor Specifies the executor that will be used to decode and process messages received from DNS servers.
     * @param _ipVersion Specifies which IP versions will be used for name servers.
     * @param _serverSpecs Specifies the parameters for recursive DNS server agents that may be used by this resolver.
     * @param _maxCacheSize Specifies the maximum DNS resource record cache size.
     * @param _maxAllowableTTLMillis Specifies the maximum allowable TTL (in milliseconds) for a resource record in the cache.
     * @param _rootHints Specifies the {@link DNSRootHints} to use.
     * @throws DNSResolverException if there is a problem instantiating {@link DNSNIO}.
     */
    private DNSResolver( final ExecutorService _executor, final DNSIPVersion _ipVersion, final List<ServerSpec> _serverSpecs,
                         final int _maxCacheSize, final long _maxAllowableTTLMillis, final DNSRootHints _rootHints ) throws DNSResolverException {

        executor      = _executor;
        nio           = new DNSNIO();
        ipVersion     = _ipVersion;
        serverSpecs   = _serverSpecs;
        activeQueries = new ConcurrentHashMap<>();
        nextQueryID   = new AtomicInteger();
        cache         = new DNSCache( _maxCacheSize, _maxAllowableTTLMillis, _rootHints );
        rootHints     = new DNSRootHints();

        // map our agent parameters by name...
        Map<String,ServerSpec> byName = new HashMap<>();
        serverSpecs.forEach( ap -> byName.put( ap.name, ap ) );
        serversByName = Collections.unmodifiableMap( byName );

        // make a list of agents sorted in descending order of priority (so the highest priority agents are first)...
        List<ServerSpec> temp = new ArrayList<>( serverSpecs );
        temp.sort( (a,b) -> b.priority - a.priority );
        serversByPriority = Collections.unmodifiableList( temp );

        // make a list of agents sorted in ascending order of timeout (so the fastest agents are first)...
        temp = new ArrayList<>( serverSpecs );
        temp.sort( Comparator.comparingLong( a -> a.timeoutMillis ) );
        serversBySpeed = Collections.unmodifiableList( temp );
    }


    // forwarded query...
    // only one question per query!
    // https://stackoverflow.com/questions/4082081/requesting-a-and-aaaa-records-in-single-dns-query/4083071#4083071
    public Outcome<?> query( final DNSQuestion _question, final BiConsumer<Outcome<QueryResult>,Object> _handler, final DNSTransport _initialTransport,
                             final DNSServerSelection _serverSelection, final Object _attachment ) {

        Checks.required( _handler );

        return queryImpl( _question, new HandlerWrapper( _handler, _attachment )::handle, _initialTransport, _serverSelection );
    }


    public Outcome<?> query( final DNSQuestion _question, final Consumer<Outcome<QueryResult>> _handler, final DNSTransport _initialTransport,
                             final DNSServerSelection _serverSelection ) {

        Checks.required( _handler );

        return queryImpl( _question, new HandlerWrapper( _handler )::handle, _initialTransport, _serverSelection );
    }


    private Outcome<?> queryImpl( final DNSQuestion _question, final Consumer<Outcome<QueryResult>> _handler,
                              final DNSTransport _initialTransport, final DNSServerSelection _serverSelection ) {

        Checks.required( _question, _initialTransport, _serverSelection );

        if( resolveFromCache( _question, _handler ) )
            return outcome.ok();

        List<ServerSpec> servers = getServers( _serverSelection );

        DNSQuery query = new DNSForwardedQuery( this, cache, nio, executor, activeQueries, _question, getNextID(), serverSpecs, _handler );

        return query.initiate( _initialTransport );
    }


    // recursive query...
    // only one question per query!
    // https://stackoverflow.com/questions/4082081/requesting-a-and-aaaa-records-in-single-dns-query/4083071#4083071
    public Outcome<?> query( final DNSQuestion _question, final BiConsumer<Outcome<QueryResult>,Object> _handler,
                             final DNSTransport _initialTransport, final Object _attachment ) {

        Checks.required( _handler );

        return queryImpl( _question, new HandlerWrapper( _handler, _attachment )::handle, _initialTransport );
    }


    public Outcome<?> query( final DNSQuestion _question, final Consumer<Outcome<QueryResult>> _handler, final DNSTransport _initialTransport ) {

        Checks.required( _handler );

        return queryImpl( _question, new HandlerWrapper( _handler )::handle, _initialTransport );
    }


    private Outcome<?> queryImpl( final DNSQuestion _question, final Consumer<Outcome<QueryResult>> _handler, final DNSTransport _initialTransport ) {

        Checks.required( _question, _initialTransport );

        if( resolveFromCache( _question, _handler ) )
            return outcome.ok();

        DNSQuery query = new DNSRecursiveQuery( this, cache, nio, executor, activeQueries, _question, getNextID(), _handler );

        return query.initiate( _initialTransport );
    }


    public int getNextID() {
        return nextQueryID.getAndIncrement();
    }


    // TODO: need to break up this logic, so we can do a pure cache search (without sending the results to the customer on success)...

    /**
     * Attempts to resolve the given question from the DNS cache, returns {@code true} if it resolved successfully.  To be resolved from the cache, the given {@link DNSQuestion}
     * must be for a discrete record type, not {@link DNSRRType#ANY} or {@link DNSRRType#UNIMPLEMENTED}.  There must be at least one result matching the question.  This method
     * will follow CNAME record chains to see if the terminus of the chain is a record matching the type in the question.  If the resolution is successful, this method synthesizes
     * a {@link DNSMessage} containing the answers retrieved from the cache and passes it to the given handler.  If the one of the handlers is called, the outcome it passes will
     * always be ok.  This method does not add any resource records to the authorities or additional records sections to the synthesized response message.
     *
     * @param _question The {@link DNSQuestion} to attempt to resolve from the DNSCache.
     * @param _handler  The {@link Consumer Consumer&lt;Outcome&lt;QueryResult&gt;&gt;} handler to call if the question is successfully resolved from the cache and
     *                  attachments are not being used.
     * @return {@code true} if the question was resolved from the cache.
     */
    private boolean resolveFromCache( final DNSQuestion _question, final Consumer<Outcome<QueryResult>> _handler ) {

        // we don't want to attempt resolving ANY queries from cache, because we can't tell if the cache has everything...
        // we don't want to attempt resolving UNIMPLEMENTED queries from cache because, well, they're unimplemented...
        if( (_question.qtype == ANY) || (_question.qtype == UNIMPLEMENTED) )
            return false;

        // get anything the cache might have from the domain we're looking for...
        List<DNSResourceRecord> cached = cache.get( _question.qname );

        // if we got nothing at all back, bail out negatively...
        if( cached.size() == 0 )
            return false;

        // we got something back from the cache, so it's possible we can resolve the question...
        // make a place to stuff our answers...
        List<DNSResourceRecord> answers = new ArrayList<>();

        // iterate over the cached records to see if any of them match what we're looking for, or match a CNAME that might point to what we need...
        cached.forEach( (rr) -> {

            // if the cached record matches the class and type in the question, stuff it directly into the answers...
            if( (rr.klass == _question.qclass) && (rr.type == _question.qtype) )
                answers.add( rr );

            // if it's a CNAME, and it's the only record we got, then we need to resolve the chain (which could be arbitrarily long)...
            // (if there's a CNAME, the DNS RFCs call for it to be the ONLY resource record with that FQDN)...
            else if( (rr.type == CNAME) && (cached.size() == 1) ) {

                // resolve the CNAME chain, recording the elements into the list answerChain...
                List<DNSResourceRecord> answerChain = new ArrayList<>();
                List<DNSResourceRecord> cached2 = new ArrayList<>( cached );
                while( (cached2.size() == 1) && (cached2.get(0).type == CNAME) ) {
                    answerChain.add( cached2.get( 0 ) );
                    cached2 = cache.get( ((com.dilatush.dns.rr.CNAME)cached2.get( 0 )).cname );
                }

                // at this point, answerChain contains 1 or more CNAME records, and cached2 contains a different kind of records, or no record...
                // so now we see if cached2 has any of the kinds of records we actually want, and if so we add them to answerChain...
                AtomicBoolean gotOne = new AtomicBoolean( false );
                cached2.stream()
                        .filter(  (arr) -> (arr.klass == _question.qclass) && (arr.type == _question.qtype) )
                        .forEach( (arr) -> { gotOne.set( true ); answerChain.add( arr ); } );

                // if we got at least one, then dump the CNAME resolution chain into our answers...
                if( gotOne.get() )
                    answers.addAll( answerChain );
            }
        } );

        // if we got no answers, then we leave, sadly, with a negative answer...
        if( answers.isEmpty() )
            return false;

        // get our synthesized query results, as we have some answers...

        // first our query message...
        DNSMessage.Builder builder = new DNSMessage.Builder();
        builder.addQuestion( _question );
        builder
            .setOpCode(     DNSOpCode.QUERY )
            .setRecurse(    true            )
            .setCanRecurse( true            );
        DNSMessage query = builder.getMessage();

        // then our response message...
        DNSMessage response = query.getSyntheticOKResponse( answers );

        // then our log...
        DNSQuery.QueryLog queryLog = new DNSQuery.QueryLog();
        queryLog.log( "Query resolved from cache: " + _question );

        // finally, we have our query result...
        QueryResult queryResult = new QueryResult( query, response, queryLog );

        // call the right handler with the result, for we are done...
        _handler.accept( outcomeQueryResult.ok( queryResult ) );

        return true;
    }


    public List<DNSResourceRecord> getRootHints() {

        Outcome<List<DNSResourceRecord>> rho = rootHints.current();

        // if we couldn't read the root hints, return a null...
        if( rho.notOk() )
            return null;

        // add all the root hint resource records to the cache...
        cache.add( rho.info() );

        return rho.info();
    }


    private List<ServerSpec> getServers( final DNSServerSelection _serverSelection ) {

        return switch( _serverSelection.strategy ) {

            case PRIORITY    -> new ArrayList<>( serversByPriority );
            case SPEED       -> new ArrayList<>( serversBySpeed );
            case ROUND_ROBIN -> new ArrayList<>( serverSpecs );
            case RANDOM      -> {
                ArrayList<ServerSpec> result = new ArrayList<>( serverSpecs );
                Collections.shuffle( result );
                yield result;
            }
            case NAMED       -> {
                ServerSpec ap = serversByName.get( _serverSelection.serverName );
                ArrayList<ServerSpec> result = new ArrayList<>( 1 );
                if( ap != null ) result.add( ap );
                yield result;
            }
        };
    }


    /**
     * Returns {@code true} if this resolver has been configured with one or more DNS servers that it can forward to.
     *
     * @return {@code true} if this resolver has been configured with one or more DNS servers that it can forward to.
     */
    public boolean hasServers() {
        return serverSpecs.size() > 0;
    }


    public boolean useIPv4() {
        return (ipVersion == IPv4) || (ipVersion == IPvBoth);
    }


    public boolean useIPv6() {
        return (ipVersion == IPv6) || (ipVersion == IPvBoth);
    }


    public void clear() {
        cache.clear();
    }


    public static DNSResolver getDefaultRecursiveResolver() {
        Builder builder = new Builder();
        return builder.getDNSResolver().info();
    }


    public static DNSResolver getDefaultForwardingResolver( final InetSocketAddress _serverAddress, final String _name ) {
        Checks.required( _serverAddress, _name );
        Builder builder = new Builder();
        builder.addDNSServer( _serverAddress, 5000, 0, _name );
        return builder.getDNSResolver().info();
    }


    /**
     * Instances of this class provide a builder for instances of {@link DNSResolver}.
     */
    public static class Builder {


        private       ExecutorService      executor;
        private final List<ServerSpec>     serverSpecs           = new ArrayList<>();
        private       DNSIPVersion         ipVersion             = IPv4;
        private       int                  maxCacheSize          = 1000;
        private       long                 maxAllowableTTLMillis = 2 * 3600 * 1000;  // two hours...
        private       DNSRootHints         rootHints             = new DNSRootHints();


        /**
         * Get an instance of {@link DNSResolver} using the current state of this builder instance.  The default  builder will produce a {@link DNSResolver} instance with
         * a single-threaded executor, no recursive DNS server agents, and a cache with a capacity of 1000 resource records and a maximum allowable TTL of two hours.
         *
         * @return the fresh, tasty new instance of {@link DNSResolver}.
         */
        public Outcome<DNSResolver> getDNSResolver() {

            // if no executor was specified, build a default executor...
            if( executor == null )
                executor = new ExecutorService();

            // try to construct the new instance (it might fail if there's a problem starting up NIO)...
            try {
                return outcomeResolver.ok( new DNSResolver( executor, ipVersion, serverSpecs, maxCacheSize, maxAllowableTTLMillis, rootHints ) );
            }
            catch( DNSResolverException _e ) {
                return outcomeResolver.notOk( "Problem creating DNSResolver", _e );
            }
        }


        /**
         * Specifies the executor that will be used to decode and process messages received from DNS servers.  The default is a single-threaded executor.
         *
         * @param _executor The executor to use when decoding and processing messages received from DNS servers.
         * @return This {@link Builder}, as a convenience for setter chaining.
         */
        public Builder setExecutor( final ExecutorService _executor ) {
            executor = _executor;
            return this;
        }


        /**
         * Specifies the versions of the Internet Protocol (IP) that the resolver will use.  The default is IP version 4 (IPv4) only.
         *
         * @param _ipVersion The {@link DNSIPVersion} that the resolver will use.
         * @return This {@link Builder}, as a convenience for setter chaining.
         */
        public Builder setIPVersion( final DNSIPVersion _ipVersion ) {
            ipVersion = _ipVersion;
            return this;
        }


        /**
         * Specifies the {@link DNSRootHints} instance that the resolver's cache will use.  The default is the instance returned by {@link DNSRootHints}'s default constructor.
         *
         * @param _rootHints The {@link DNSRootHints} instance that the resolver's cache will use.
         * @return This {@link Builder}, as a convenience for setter chaining.
         */
        public Builder setRootHints( final DNSRootHints _rootHints ) {
            rootHints = _rootHints;
            return this;
        }


        /**
         * Specifies the maximum DNS resource record cache size.  The default is 1,000 resource records.
         *
         * @param _maxCacheSize The maximum DNS resource record cache size.
         * @return This {@link Builder}, as a convenience for setter chaining.
         */
        public Builder setMaxCacheSize( final int _maxCacheSize ) {
            maxCacheSize = _maxCacheSize;
            return this;
        }


        /**
         * Specifies the maximum allowable TTL (in milliseconds) for a resource record in the cache.  The default is two hours.
         *
         * @param _maxAllowableTTLMillis  the maximum allowable TTL for a resource record in the cache.
         * @return This {@link Builder}, as a convenience for setter chaining.
         */
        public Builder setMaxAllowableTTLMillis( final long _maxAllowableTTLMillis ) {
            maxAllowableTTLMillis = _maxAllowableTTLMillis;
            return this;
        }


        /**
         * Add the given parameters for a recursive DNS server agent to the list of agent parameters contained in this builder.  The list of agent parameters determines the
         * recursive DNS servers that the {@link DNSResolver} instance will be able to use.
         *
         * @param _serverAddress The IP address of the recursive DNS server.
         * @param _timeoutMillis The maximum time (in milliseconds) to wait for responses from the recursive DNS server.
         * @param _priority The priority of this recursive DNS server, with larger numbers meaning higher priority.  The priority is used with
         * {@link DNSServerSelectionStrategy#PRIORITY}.
         * @param _name The human-readable name for this recursive DNS server, used in log entries.
         */
        public void addDNSServer( final InetSocketAddress _serverAddress, final long _timeoutMillis, final int _priority, final String _name ) {

            Checks.required( _serverAddress, _name );

            serverSpecs.add( new ServerSpec( _timeoutMillis, _priority, _name, _serverAddress ) );
        }
    }


    private static class HandlerWrapper {

        private final Consumer<Outcome<QueryResult>>          handler1;
        private final BiConsumer<Outcome<QueryResult>,Object> handler2;
        private final boolean                                 useAttachment;
        private final Object                                  attachment;
        private final AtomicBoolean                           handled;


        private HandlerWrapper( final BiConsumer<Outcome<QueryResult>,Object> _handler, final Object _attachment ) {
            Checks.required( _handler );
            handler1      = null;
            handler2      = _handler;
            useAttachment = true;
            attachment    = _attachment;
            handled       = new AtomicBoolean();
        }


        private HandlerWrapper( final Consumer<Outcome<QueryResult>> _handler ) {
            Checks.required( _handler );
            handler1      = _handler;
            handler2      = null;
            useAttachment = false;
            attachment    = null;
            handled       = new AtomicBoolean();
        }


        private void handle( final Outcome<QueryResult> _outcome ) {
            boolean alreadyDone = handled.getAndSet( true );
            if( alreadyDone ) {
                LOGGER.severe( "Handler called more than once" );
                return;
            }
            if( useAttachment )
                handler2.accept( _outcome, attachment );
            else
                handler1.accept( _outcome );
        }
    }


    /**
     * A simple record to hold the parameters required to construct a {@link DNSServerAgent} instance.
     */
    public record ServerSpec( long timeoutMillis, int priority, String name, InetSocketAddress serverAddress ){}
}
