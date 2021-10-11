package com.dilatush.dns.query;

import com.dilatush.dns.DNSResolver;
import com.dilatush.dns.message.*;
import com.dilatush.dns.misc.DNSCache;
import com.dilatush.dns.misc.DNSResolverError;
import com.dilatush.dns.misc.DNSResolverException;
import com.dilatush.dns.rr.*;
import com.dilatush.util.Checks;
import com.dilatush.util.ExecutorService;
import com.dilatush.util.General;
import com.dilatush.util.Outcome;

import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.UnknownHostException;
import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Consumer;
import java.util.logging.Logger;

import static com.dilatush.dns.DNSResolver.ServerSpec;
import static com.dilatush.dns.message.DNSResponseCode.*;
import static com.dilatush.dns.misc.DNSResolverError.NETWORK;
import static com.dilatush.dns.query.DNSTransport.UDP;
import static com.dilatush.util.General.breakpoint;
import static java.util.logging.Level.FINER;
import static java.util.logging.Level.FINEST;

/**
 * Instances of this class contain the elements and state of a recursive DNS query, and provide methods that implement the resolution of that query.
 */
public class DNSRecursiveQuery extends DNSQuery {

    private static final Logger       LOGGER                           = General.getLogger();
    private static final long         RECURSIVE_NAME_SERVER_TIMEOUT_MS = 5000;
    private static final int          DNS_SERVER_PORT                  = 53;
    private static final Inet4Address INVALID_IP;

        // Oh, how do I hate exceptions?  Let me count the ways...
        static {
            Inet4Address wildcard = null;
            try {
                wildcard = (Inet4Address) InetAddress.getByName( "0.0.0.0" );
            }
            catch( UnknownHostException _e ) {
                // impossible; we're just making the compiler happy...
            }
            INVALID_IP = wildcard;
        }

    private static final Outcome.Forge<QueryResult> queryOutcome = new Outcome.Forge<>();


    private final List<InetAddress>       nextNameServerIPs;     // IP addresses of the next name servers to query...
    private final AtomicInteger           subQueries;            // the number of sub-queries currently running...
    private final List<DNSResourceRecord> answers;               // the answers to this query...

    private       boolean                 haveQueriedNSIPs;      // true if we have already queried for name server IP addresses...
    private       Map<String,InetAddress> nameServerIPMap;       // map of name servers to IP addresses, with wild card IP for those we don't have addresses for...


    /**
     * Create a new instance of this class with the given parameters.
     *
     * @param _resolver The {@link DNSResolver} responsible for creating this query.  This reference provides the query access to some of the resolver's methods and fields.
     * @param _cache The {@link DNSCache} owned by the resolver  This reference provides access for the query to use cached resource records to resolve the query (fully or
     *               partially), and to add new resource records received from other DNS servers.
     * @param _nio The {@link DNSNIO} to use for all network I/O.  This reference can be passed along to the {@link DNSServerAgent}s that need it.
     * @param _executor The {@link ExecutorService} to be used for processing received messages, to keep the load on the NIO thread to a minimum.
     * @param _activeQueries The {@link DNSResolver}'s map of currently active queries.  This reference allows the query to update the map.  The map has a peculiar purpose: to
     *                       keep a reference to any active queries, as the resolver otherwise keeps none.
     * @param _question The {@link DNSQuestion} to be resolved by this query.
     * @param _id The unique identifying 32-bit integer for this query.  The DNS specifications call for this ID to help the resolver match incoming responses to the query that
     *            produced them.  In this implementation, the matching is done by the fact that each query has a unique port number associated with it, so the ID isn't needed at
     *            all for matching.  Nevertheless, it has an important purpose: it is the key for the active query map described above.
     * @param _handler The {@link Consumer Consumer&lt;Outcome&lt;QueryResult&gt;&gt;} handler that will be called when the query is completed.  Note that the handler is called
     *                 either for success or failure.
     */
    public DNSRecursiveQuery( final DNSResolver _resolver, final DNSCache _cache, final DNSNIO _nio, final ExecutorService _executor,
                              final Map<Short,DNSQuery> _activeQueries, final DNSQuestion _question, final int _id,
                              final Consumer<Outcome<QueryResult>> _handler ) {
        super( _resolver, _cache, _nio, _executor, _activeQueries, _question, _id, new ArrayList<>(), _handler );

        nextNameServerIPs = new ArrayList<>();
        subQueries        = new AtomicInteger();
        answers           = new ArrayList<>();

        haveQueriedNSIPs  = false;

        queryLog.log("New recursive query " + question );
    }


    /**
     * Initiates a query using the given transport (UDP or TCP).  Note that a call to this method may result in several messages to DNS servers and several responses from them.
     * This may happen if a queried DNS server doesn't respond within the timeout time, or if a series of DNS servers must be queried to get the answer to the question this
     * query is trying to resolve.
     *
     * @param _initialTransport The initial transport (UDP or TCP) to use when resolving this query.
     * @return The {@link Outcome Outcome&lt;?&gt;} of this operation.
     */
    public Outcome<?> initiate( final DNSTransport _initialTransport ) {

        Checks.required( _initialTransport, "initialTransport");

        queryLog.log("Initial query" );
        LOGGER.finer( "Initiating new recursive query - ID: " + id + ", " + question.toString() );

        initialTransport = _initialTransport;

        return query();
    }


    /**
     * Send the query to the DNS server, returning an {@link Outcome Outcome&lt;?&gt;} with the result.  Generally the outcome will be "not ok" only if there is some problem
     * with the network or connection to a specific DNS server.
     *
     * @return The {@link Outcome Outcome&lt;?&gt;} result.
     */
    protected Outcome<?> query() {

        // if we already had an agent running, shut it down...
        if( agent != null )
            agent.close();

        transport = initialTransport;

        LOGGER.finer( "Recursive query - ID: " + id + ", " + question.toString() );

        DNSMessage.Builder builder = new DNSMessage.Builder();
        builder
            .setOpCode(   DNSOpCode.QUERY )
            .setRecurse(  false           )
            .setId(       id & 0xFFFF     )
            .addQuestion( question );

        queryMessage = builder.getMessage();

        // try to resolve the query through the cache...
        DNSMessage cacheResponse = cache.resolve( queryMessage );

        queryLog.log( "Resolved from cache: response code: " + cacheResponse.responseCode + ", " + cacheResponse.answers.size() + " answers, " + cacheResponse.authorities.size()
            + " authorities, " + cacheResponse.additionalRecords.size() + " additional records" );

        // if the response code is SERVER_FAILURE, then we couldn't get the root hints - that's fatal; let the user know...
        if( cacheResponse.responseCode == SERVER_FAILURE ) {
            String msg = "Could not get root hints from cache";
            queryLog.log( msg );
            return outcome.notOk( msg, new DNSResolverException( msg, DNSResolverError.ROOT_HINTS_PROBLEMS ) );
        }

        // if the response code is FORMAT_ERROR, then the query is malformed - that's fatal; let the user know...
        if( cacheResponse.responseCode == FORMAT_ERROR ) {
            String msg = "Query is malformed";
            queryLog.log( msg );
            return outcome.notOk( msg, new DNSResolverException( msg, DNSResolverError.BAD_QUERY ) );
        }

        // if the response code is OK, and we have some answers, then we're done...
        if( (cacheResponse.responseCode == OK) && (cacheResponse.answers.size() > 0) ) {
            queryLog.log( "Resolved from cache: " + question );
            handler.accept( queryOutcome.ok( new QueryResult( queryMessage, cacheResponse, queryLog ) ) );
            return outcome.ok();
        }

        /* ------------------------------------------------------------------------------------------------------------------------
         * If we get here, then we should have an OK response with no answers, at least one name server in authorities, and possibly
         * one or more additional records with IP addresses (of the name servers).  The algorithm from here goes about like this:
         *
         *    if we don't have enough IP addresses for the authoritative name servers
         *       make sub-queries to get the needed IP addresses
         *    query the authoritative name servers one at a time, until we get some answers
         *    cache the answers
         *    re-issue the original query
         *
         * By updating the cache above, we're providing more information pertinent to the original query.  We'll be one step closer
         * to resolving it.  The algorithm above may need to be repeated several times before the query is resolved.  At worst case,
         * it will need to be repeated 'n' times, where 'n' is the number of labels in the domain name being queried.  Better cases
         * occur because some information has previously been cached.
         *
         * Above we refer to "enough IP addresses for the name servers".  What we mean by that is either an IP address for every
         * name server, or at least two name servers with IP addresses.  This is just a heuristic to attempt to guarantee that we
         * can successfully query an authoritative name server.  It's common for the authorities to contain more than two name
         * servers, and relatively uncommon for the authorities to have just one.  Sometimes the resource records for those name
         * servers have very short (a few seconds) TTLs; this is most common when CDNs are in use.
         * ------------------------------------------------------------------------------------------------------------------------ */

        // make sure we got a valid-looking answer...
        if( (cacheResponse.responseCode != OK) || (cacheResponse.authorities.size() == 0) ) {
            String msg = "No name servers available for resolving " + cacheResponse.getQuestion().qclass.text;
            queryLog.log( msg );
            return outcome.notOk( msg, new DNSResolverException( msg, DNSResolverError.NO_NAME_SERVERS ) );
        }

        // see if we need to sub-query for name server IP addresses - but don't do it more than once...
        if( !haveEnoughNameServerIPs( cacheResponse ) && !haveQueriedNSIPs )
            return subQueryForNameServerIPs();

        // clear this flag, so that if we have to sub-query for a more specific label we won't think we've already done it...
        haveQueriedNSIPs = false;

        // if we make it here, we have enough name server IPs to actually go query for the next stage of our recursive resolution - so we make a list of server specs for
        // name servers that we could query, and we start that process going...

        // iterate over the entries in our name server IP address map, and generate server specs for those we have IP addresses for...
        serverSpecs.clear();
        nameServerIPMap.entrySet()
            .stream()
            .filter( (entry) -> entry.getValue() != INVALID_IP )                                                   // we're skipping those with the INVALID_IP...
            .forEach( (entry) -> {
                InetSocketAddress socket = new InetSocketAddress( entry.getValue(), DNS_SERVER_PORT );             // turn the IP address into a socket address...
                ServerSpec spec = new ServerSpec( RECURSIVE_NAME_SERVER_TIMEOUT_MS, 0, entry.getKey(), socket );   // get a server spec for our name server...
                serverSpecs.add( spec );                                                                           // add it to our hoppy list of servers...
            } );
        queryLog.log( "Starting query of \"" + cacheResponse.authorities.get( 0 ).name.text + "\" authorities; " + serverSpecs.size() + " name server authorities available" );

        // now we kick things off by querying the first DNS server...
        return queryNextDNSServer();
   }


    /**
     * Send the query to the next DNS server on the list of {@link ServerSpec}s.
     *
     * @return Ok unless there are no more DNS servers to query, or if the query could not be sent for some reason.
     */
   private Outcome<?> queryNextDNSServer() {

        // if we have no more DNS servers left to query, we've got a problem...
       if( serverSpecs.size() == 0 ) {
           String msg = "No DNS server responded, and there are no more DNS servers to try";
           queryLog.log( msg );
           return outcome.notOk( msg, new DNSResolverException( msg, DNSResolverError.NO_NAME_SERVERS ) );
       }

       // figure out what agent we're going to use...
       agent = new DNSServerAgent( resolver, this, nio, executor, serverSpecs.remove( 0 ) );

       queryLog.log( "Sending recursive query for " + question + " to " + agent.name + " via " + transport );

       Outcome<?> sendOutcome = agent.sendQuery( queryMessage, transport );

       return sendOutcome.ok()
               ? queryOutcome.ok( new QueryResult( queryMessage, null, queryLog ) )
               : queryOutcome.notOk( sendOutcome.msg(), new DNSResolverException( sendOutcome.msg(), sendOutcome.cause(), DNSResolverError.BAD_QUERY ) );
   }


    /**
     * Analyzes the given response message, extracting the name servers from the authorities section, and the IP addresses for the name servers from the additional records
     * section.  Builds the {@link #nameServerIPMap} from that information, and also attempts to resolve IP addresses from the cache for any name servers that the response didn't
     * provide IP addresses for.  Returns {@code true} if there are enough IP addresses (that is, there is an IP address for every name server, or there are at least two IP
     * addresses).
     *
     * @param _response The {@link DNSMessage} response message to analyze.
     * @return {@code true} if there are enough IP addresses.
     */
   private boolean haveEnoughNameServerIPs( final DNSMessage _response ) {

       // build a map of all the name servers in the response, with the name server host name as the key and the invalid IP (0.0.0.0, which can never belong to a name server)...
       nameServerIPMap = new HashMap<>();   // map name server host names to IPs...
       _response.authorities
               .stream()
               .filter( (rr) -> rr instanceof NS)
               .forEach( (rr) -> nameServerIPMap.put( ((NS)rr).nameServer.text, INVALID_IP )
       );

       // associate any IP addresses in the response with the name servers...
       _response.additionalRecords.forEach( (rr) -> {
           if( nameServerIPMap.containsKey( rr.name.text ) ) {
               if( (rr instanceof A) && resolver.useIPv4() )
                   nameServerIPMap.put( rr.name.text, ((A)rr).address );
               else if( (rr instanceof AAAA) && resolver.useIPv6() )
                   nameServerIPMap.put( rr.name.text, ((AAAA)rr).address );
           }
       } );

       // try resolving name server IPs from the cache, for those name server IPs we didn't get in the response...
       nameServerIPMap.entrySet()
               .stream()
               .filter( (entry) -> { return entry.getValue() == INVALID_IP; } )    // the == works here, because we're looking for occurrences of the same instance...
               .forEach( (entry) -> {

                   // get a list of all the IPs the cache has for this name server host name...
                   List<DNSResourceRecord> ips = switch( resolver.getIpVersion() ) {
                       case IPv4 ->    cache.get( entry.getKey(), DNSRRType.A                 );
                       case IPv6 ->    cache.get( entry.getKey(), DNSRRType.AAAA              );
                       case IPvBoth -> cache.get( entry.getKey(), DNSRRType.A, DNSRRType.AAAA );
                   };

                   // if we actually got some IPs, associate the first one with the name server...
                   if( ips.size() > 0 ) {
                       DNSResourceRecord iprr = ips.get( 0 );
                       InetAddress nsip = (iprr instanceof A) ? ((A)iprr).address : ((AAAA)iprr).address;
                       entry.setValue( nsip );
                   }
               } );

       // we now have one or more name servers, with zero or more associated IP addresses - time to see if we have enough, or if we need to sub-query...
       long ipCount = nameServerIPMap.values().stream().filter( (ip) -> ip != INVALID_IP ).count();  // count the associated IPs...
       return (ipCount == nameServerIPMap.size()) || (ipCount >= 2);
   }


    /**
     * Issue sub-queries for the IP addresses (either IPv4 or IPv6, according to our configuration) for all the name servers that we have that don't already have an IP address.
     * Note that these sub-queries will execute asynchronously, and this query will not proceed until all the sub-queries have completed or timed out.
     *
     * @return The outcome, which will be ok unless one or more of the sub-queries failed.
     */
   private Outcome<?> subQueryForNameServerIPs() {

       // we assume a good outcome until and if we get a bad one below...
       var result = new Object() {
           Outcome<?> result = outcome.ok();
       };

       nameServerIPMap.entrySet()
               .stream()
               .filter( (entry) -> entry.getValue() == INVALID_IP )
               .forEach( (entry) -> {

                   // fire off the query for the A record...
                   if( resolver.useIPv4() ) {
                       subQueries.incrementAndGet();
                       String msg = "Firing " + entry.getKey() + " A record sub-query " + subQueries.get() + " from query " + id;
                       LOGGER.finest( msg );
                       queryLog.log( msg );
                       DNSQuestion aQuestion = new DNSQuestion( DNSDomainName.fromString( entry.getKey() ).info(), DNSRRType.A );
                       DNSRecursiveQuery recursiveQuery
                               = new DNSRecursiveQuery( resolver, cache, nio, executor, activeQueries, aQuestion, resolver.getNextID(), this::handleNSResolutionSubQuery );
                       Outcome<?> resultInt = recursiveQuery.initiate( UDP );
                       if( resultInt.notOk() )
                           result.result = resultInt;
                   }

                   // fire off the query for the AAAA record...
                   if( resolver.useIPv6() ) {
                       subQueries.incrementAndGet();
                       String msg = "Firing " + entry.getKey() + " AAAA record sub-query " + subQueries.get() + " from query " + id;
                       LOGGER.finest( msg );
                       queryLog.log( msg );
                       DNSQuestion aQuestion = new DNSQuestion( DNSDomainName.fromString( entry.getKey() ).info(), DNSRRType.AAAA );
                       DNSRecursiveQuery recursiveQuery
                               = new DNSRecursiveQuery( resolver, cache, nio, executor, activeQueries, aQuestion, resolver.getNextID(), this::handleNSResolutionSubQuery );
                       Outcome<?> resultInt = recursiveQuery.initiate( UDP );
                       if( resultInt.notOk() )
                           result.result = resultInt;
                   }
       } );

       // remember that we've queried for these IPs, so we don't do it more than once...
       haveQueriedNSIPs = true;

       return result.result;
   }


    /**
     * Response handler for responses to this query (not sub-queries).  There are several possible sorts of responses:
     * <ul>
     *     <li>Response code OK, answer authoritative, with answers: the original query has been satisfied and we can return the answers to the caller.</li>
     *     <li>Response code NAME_ERROR, answer authoritative: the domain name being queried does not exist; we need to return that information to the caller.</li>
     *     <li>Response code OK, no answers, at least one authority, possibly some additional records: one more step on the recursive resolution trail; we need to update the
     *     cache and try querying again.</li>
     *     <li>The message was received on UDP and was truncated; retry the query on TCP.</li>
     *     <li>The message was received on a different transport than was expected: an error; must be reported to the caller.</li>
     * </ul>
     *
     * @param _responseMsg The {@link DNSMessage} received from a DNS server.
     * @param _transport The transport (UDP or TCP) that the message was received on.
     */
   protected void handleResponse( final DNSMessage _responseMsg, final DNSTransport _transport ) {

       Checks.required( _responseMsg, _transport );

       String msg = "Received response via " + _transport + ": " + _responseMsg.toString();
       queryLog.log( msg );
       LOGGER.finer( msg );

       // no matter what happens next, we need to shut down the agent...
       agent.close();

       // stuff the response away...
       responseMessage = _responseMsg;

       // if the message came in on the wrong transport, that's an error...
       if( _transport != transport ) {
           handleWrongTransport( _transport );
           return;
       }

       // if our UDP response was truncated, retry it with TCP - we're not done yet...
       if( (transport == UDP) && _responseMsg.truncated ) {
           handleTruncatedMessage();
           return;
       }

       // if we make it here, then we need to figure out what the message is trying to tell use...

       // if it's OK, we have no answers, but we have at least one authority, then it's time to take the next step on our recursive journey...
       if( (responseMessage.responseCode == OK) && (responseMessage.answers.size() == 0) && (responseMessage.authorities.size() > 0) ) {

           // update the cache with all this lovely information we just received...
           updateCacheFromMessage( responseMessage );

           // now we'll retry the query...
           Outcome<?> qo = query();

           // if it failed, then we have to tell our caller that things just didn't work out...
           if( qo.notOk() ) {
               handler.accept( queryOutcome.notOk(
                       "Problem sending recursive query: " + qo.msg(),
                       new DNSResolverException( qo.msg(), DNSResolverError.BAD_QUERY ),
                       new QueryResult( queryMessage, null, queryLog ) ) );
           }
       }

       // if it's OK, authoritative, and we have at least one answer, then we've finished our recursive journey and it's time to give our caller what he asked for...
       else if( (responseMessage.responseCode == OK) && (responseMessage.answers.size() > 0) && responseMessage.authoritativeAnswer ) {

           updateCacheFromMessage( responseMessage );
           handler.accept( queryOutcome.ok( new QueryResult( queryMessage, responseMessage, queryLog )) );
       }

       // if it's a NAME_ERROR, and authoritative, then it's time to disappoint our caller...
       else if( (responseMessage.responseCode == NAME_ERROR) && responseMessage.authoritativeAnswer ) {

       }

       // otherwise, it's something we don't understand, so log it and tell our caller we've failed...
       else {

       }


       breakpoint();
   }


    /**
     * Called when there is a problem of some kind that occurs before a message is received and decoded.  That means we don't have a lot of context for the error, but we still
     * need to try another server, or (if we run out of servers to try), to do some cleanup and tell the customer what happened.
     *
     * @param _msg A message describing the problem.
     * @param _cause An optional {@link Throwable} cause.
     */
    protected void handleProblem( final String _msg, final Throwable _cause ) {

        queryLog.log( _msg + ((_cause != null) ? " - " + _cause.getMessage() : "") );

        // while we've got more servers to try...
        while( !serverSpecs.isEmpty() ) {

            // resend the query to the next server...
            Outcome<?> qo = query();

            // if it was sent ok, we're done...
            if( qo.ok() )
                return;
        }

        // if we get here, we ran out of servers to try - clean up and tell the customer what happened...

        // some cleanup...
        agent.close();
        activeQueries.remove( (short) id );

        queryLog.log("No more DNS servers to try" );
        handler.accept(
                queryOutcome.notOk(
                        _msg,
                        new DNSResolverException( _msg, _cause, NETWORK ),
                        new QueryResult( queryMessage, null, queryLog )
                )
        );
    }


    /**
     * Called when the response message has an "OK" response code.  Adds the results (answers, authorities, and additional records) to the cache, then handles the rather
     * complicated logic that implements recursive querying.
     */
    protected void handleOK() {
        super.handleOK();

        // if we have some answers (or we have none, but the response was authoritative), then let's see if we're done, or if we're resolving a CNAME chain...
        if( !responseMessage.answers.isEmpty() || responseMessage.authoritativeAnswer ) {
            handleAnswers();
            return;
        }

        // If we get here, then what we SHOULD have is one or more NS records in the authorities, which is the DNS server telling us that those name servers can take our
        // query further than it could.  We MIGHT also have one or more A or AAAA records in additional records, which are the IP addresses of the name servers in the
        // authorities section.
        //
        // So what we're going to do now is to see if we have NS records with no resolved IP address (from an A or AAAA record).  If we DO have such NS records, then we're
        // going to make sub-queries to resolve them.  Once we've got the responses to those queries, we'll make a list of name servers with IPs, and use them to take the
        // next step on our query's journey.

        // get a set of all the name servers that we just found out about...
        Set<String> allNameServers = new HashSet<>();
        String[] nsDomain = new String[1];
        responseMessage.authorities.forEach( (rr) -> {
            if( rr instanceof NS ) {
                allNameServers.add( ((NS)rr).nameServer.text );
                nsDomain[0] = rr.name.text;
            }
        });

        // if we have no name server records, then we've got a real problem...
        if( allNameServers.isEmpty() ) {
            queryLog.log( "No name server records received" );
            handler.accept(
                    queryOutcome.notOk(
                            "No name server records received from " + agent.name,
                            null,
                            new QueryResult( queryMessage, responseMessage, queryLog ) )
            );
        }

        queryLog.log( "Got " + allNameServers.size() + " name server(s) for '" + nsDomain[0] + "'" );

        // build a list of everything we know about the name servers we got in authorities...
        List<DNSResourceRecord> nsInfo = new ArrayList<>( responseMessage.additionalRecords );
        allNameServers.forEach( (ns) -> nsInfo.addAll( cache.get( ns ) ) );

        // now check any IPs we got from the cache or in additional records, building a list of IPs for name servers, and a set of resolved name servers...
        Set<String> resolvedNameServers = new HashSet<>();
        nextNameServerIPs.clear();
        nsInfo.forEach( (rr) -> {
            if( (rr instanceof A) || (rr instanceof AAAA) ) {
                if( allNameServers.contains( rr.name.text ) ) {
                    if( resolver.useIPv4() && (rr instanceof A))
                        nextNameServerIPs.add( ((A)rr).address );
                    if( resolver.useIPv6() && (rr instanceof AAAA))
                        nextNameServerIPs.add( ((AAAA)rr).address );
                    resolvedNameServers.add( rr.name.text );
                }
            }
        } );

        // build a set of the unresolved name servers...
        Set<String> unresolvedNameServers = new HashSet<>( allNameServers );
        unresolvedNameServers.removeAll( resolvedNameServers );

        LOGGER.finest( "Name servers (all, resolved, unresolved): " + allNameServers.size() + ", " + resolvedNameServers.size() + ", " + unresolvedNameServers.size() );

        // if we don't have any unresolved name servers, then we can just start the next query going...
        if( unresolvedNameServers.isEmpty() ) {
            //startNextQuery();
            return;
        }

        // we DO have unresolved name servers, so blast out sub-queries to resolve them

        // TODO: try to resolve from cache before firing off sub-queries
        // send out the sub-queries...
        unresolvedNameServers.forEach( (unresolvedNameServer) -> {

            // get a DNSDomainName instance from the unresolved name server string; we know the outcome will be ok, so we just grab the info...
            DNSDomainName nsDomainName = DNSDomainName.fromString( unresolvedNameServer ).info();

            // fire off the query for the A record...
            if( resolver.useIPv4() ) {
                subQueries.incrementAndGet();
                LOGGER.finest( "Firing " + nsDomainName.text + " A record sub-query " + subQueries.get() + " from query " + id );
                DNSQuestion aQuestion = new DNSQuestion( nsDomainName, DNSRRType.A );
                DNSRecursiveQuery recursiveQuery = new DNSRecursiveQuery( resolver, cache, nio, executor, activeQueries, aQuestion, resolver.getNextID(), this::handleNSResolutionSubQuery );
                recursiveQuery.initiate( UDP );
            }

            // fire off the query for the AAAA record...
            if( resolver.useIPv6() ) {
                subQueries.incrementAndGet();
                LOGGER.finest( "Firing " + nsDomainName.text + " AAAA record sub-query " + subQueries.get() + " from query " + id );
                DNSQuestion aQuestion = new DNSQuestion( nsDomainName, DNSRRType.AAAA );
                DNSRecursiveQuery recursiveQuery = new DNSRecursiveQuery( resolver, cache, nio, executor, activeQueries, aQuestion, resolver.getNextID(), this::handleNSResolutionSubQuery );
                recursiveQuery.initiate( UDP );
            }
        } );
    }


    private void doneWithAnswers() {
        queryLog.log( "Got viable answers" );
        responseMessage = queryMessage.getSyntheticOKResponse( answers );
        handler.accept( queryOutcome.ok( new QueryResult( queryMessage, responseMessage, queryLog )) );
        activeQueries.remove( (short) id );
    }


    private void doneWithProblem( final String _msg ) {
        queryLog.log( "Problem with answers: " + _msg );
        handler.accept( queryOutcome.notOk( _msg, null, new QueryResult( queryMessage, null, queryLog ) ) );
        activeQueries.remove( (short) id );
    }


    /**
     * Inspects the records in the accumulated answers to make certain that if there are CNAME records, they are correctly chained.  Returns {@code true} if they are;
     * otherwise sends a not ok outcome and returns {@code false}.
     *
     * @return {@code true} if the answers are correctly chained.
     */
    private boolean isProperChaining() {

        String expectedDomain = question.qname.text;

        for( DNSResourceRecord rr : answers ) {

            if( !expectedDomain.equals( rr.name.text ) ) {
                doneWithProblem( "Invalid CNAME chain" );
                return false;
            }

            if( rr instanceof CNAME )
                expectedDomain = ((CNAME) rr).cname.text;
            else
                break;
        }
        return true;
    }


    /**
     * Returns {@code true} if the accumulated answers do not contain a CNAME loop, otherwise sends a not ok outcome and returns {@code false}.
     *
     * @return {@code true} if the accumulated answers do not contain a CNAME loop.
     */
    private boolean isLoopless() {

        Set<String> cnameDomains = new HashSet<>();
        for( DNSResourceRecord rr : answers ) {
            if( rr instanceof CNAME) {
                String dn = rr.name.text;
                if( cnameDomains.contains( dn ) ) {
                    doneWithProblem( "CNAME loop, starting with: " + dn );
                    return false;
                }
                cnameDomains.add( dn );
            }
        }
        return true;
    }


    private void handleAnswers() {
//
//        LOGGER.finest( "Got some answers: " + responseMessage.answers.size() );
//
//        // first we accumulate the answers from the message we just received with any that we've received from previous queries or sub-queries...
//        answers.addAll( responseMessage.answers );
//
//        // There are several possible scenarios here, which must be checked in the order given:
//        // 1. There are zero answers, which means the query was answered but there were no results.
//        // 2. There are one or more answers, and the desired type is ANY or CNAME, or they're all the desired type. In this case, we accumulate all the answers, and we're done.
//        // 3. There are two or more answers, consisting of one or more CNAME records followed by one or more answers of the desired type.  In this case, we check for proper
//        //    CNAME chaining, accumulate all the answers, and we're done.
//        // 4. There are one or more answers, all of which are CNAME records.  In this case, the last CNAME is a referral, we accumulate all the answers, check for a CNAME
//        //    loop (which is an error), and then fire off a sub-query to resolve the referral.  The results of the sub-query are evaluated exactly as the results of the
//        //    first query.
//        // 5. There are one or more answers which are neither CNAME records nor the desired type.  This is an error.
//
//        // now we do a little analysis on our accumulated answers, so we can figure out what to do next...
//        AnswersAnalysis aa = analyzeAnswers();
//
//        // if we got no answers, we're done...
//        if( responseMessage.answers.size() == 0 ) {
//            doneWithAnswers();
//            return;
//        }
//
//        // If the desired type is ANY or CNAME, or all the records are the type we want, then we're done...
//        if( (question.qtype == DNSRRType.ANY) || (question.qtype == DNSRRType.CNAME) || (aa.desiredCount == answers.size())) {
//            doneWithAnswers();
//            return;
//        }
//
//        // if we've got one or more CNAME records followed by one or more records of our desired type, then we check for proper CNAME chaining, and we're done...
//        if( (aa.cnameCount > 0) && (aa.desiredCount > 0) && !aa.bogus ) {
//
//            // make sure our CNAME records chain properly in the order we have them, to the first record of the desired type...
//            if( !isProperChaining() )
//                return;
//
//            // otherwise, send our excellent answers back...
//            doneWithAnswers();
//            return;
//        }
//
//        // TODO: try to resolve from cache before firing off a subquery...
//        // if we have one or more CNAME records and nothing else, check for a CNAME loop, then fire a sub-query to the last (unresolved) domain...
//        if( aa.cnameCount == answers.size() ) {
//
//            // if we have a CNAME loop, that's a fatal error...
//            if( !isLoopless() )
//                return;
//
//            // send off a sub-query to get the next element of the CNAME chain, or our actual answer...
//            DNSDomainName nextDomain = ((CNAME)answers.get( answers.size() - 1 )).cname;
//            DNSRRType nextType = question.qtype;
//
//            LOGGER.finest( "Firing " + nextDomain.text + " " + nextType + " record sub-query " + subQueries.get() + " from query " + id );
//            DNSQuestion aQuestion = new DNSQuestion( nextDomain, nextType );
//            DNSRecursiveQuery recursiveQuery = new DNSRecursiveQuery( resolver, cache, nio, executor, activeQueries, aQuestion, resolver.getNextID(),
//                    this::handleChainSubQuery );
//            recursiveQuery.initiate( UDP );
//            return;
//        }
//
//        // if we have one or more records that are neither CNAME nor our desired record type, we have an error...
//        if( aa.wrongCount > 0 ) {
//            doneWithProblem( "Unexpected record types in answers" );
//            return;
//        }
//
//        // if we get here, we have a condition that we didn't cover in the logic above - big problem...
//        doneWithProblem( "Unexpected condition in answers" );
    }


    private void handleChainSubQuery( final Outcome<QueryResult> _outcome ) {

        LOGGER.log( FINER, "Entered handleChainSubQuery, " + (_outcome.ok() ? "ok" : "not ok") );
        String logMsg = "Handling outcome of chain sub-query " + _outcome.info().query().toString()
                + ((_outcome.info().response() != null) ? "\nResponse: " + _outcome.info().response() : "");
        LOGGER.log( FINEST, logMsg );

        // if the outcome was not ok, then we have a failed query...
        if( _outcome.notOk() ) {
            queryLog.log( "Bad outcome on chain sub-query: " + _outcome.msg() );
            handler.accept( queryOutcome.notOk( _outcome.msg(), null, new QueryResult( queryMessage, null, queryLog ) ) );
            activeQueries.remove( (short) id );
            queryLog.log( "Chain sub-query" );
            queryLog.addSubQueryLog( _outcome.info().log() );
            return;
        }

        // whatever happened, log the sub-query...
        queryLog.log( "Chain sub-query" );
        queryLog.addSubQueryLog( _outcome.info().log() );

        // process the answers; we could be done, or we could need another query...
        responseMessage = _outcome.info().response();
        handleAnswers();
    }


    /**
     * Handle the outcome of a sub-query for name server resolution.  Note that if the executor is configured with multiple threads, then it's possible for multiple threads to
     * execute this method concurrently; hence the synchronization.
     *
     * @param _outcome The {@link Outcome Outcome&lt;QueryResult&gt;} of the sub-query.
     */
    private void handleNSResolutionSubQuery( final Outcome<QueryResult> _outcome ) {

        LOGGER.log( FINER, "Entered handleSubQuery, " + (_outcome.ok() ? "ok" : "not ok") );
        String logMsg = "Query " + _outcome.info().query().toString()
                + ((_outcome.info().response() != null) ? "\nResponse: " + _outcome.info().response() : "");
        LOGGER.log( FINEST, logMsg );

        synchronized( this ) {

            // if we got a good result, then add any IPs we got to the cache...
            DNSMessage response = _outcome.info().response();
            if( _outcome.ok() && (response != null) )
                cache.add( response.answers );

            // whatever happened, log the sub-query...
            queryLog.log( "Name server resolution sub-query" );
            queryLog.addSubQueryLog( _outcome.info().log() );
        }

        // decrement our counter, and if we're done, try sending the next query...
        int queryCount = subQueries.decrementAndGet();
        LOGGER.fine( "Sub-query count: " + queryCount );
        if( queryCount == 0 ) {

            // now we'll retry the query...
            Outcome<?> qo = query();

            // if it failed, then we have to tell our caller that things just didn't work out...
            if( qo.notOk() ) {
                handler.accept( queryOutcome.notOk(
                        "Problem sending recursive query: " + qo.msg(),
                        new DNSResolverException( qo.msg(), DNSResolverError.BAD_QUERY ),
                        new QueryResult( queryMessage, null, queryLog ) ) );
            }
        }
    }


    /**
     * Add the name server IP addresses contained in any A (if IPv4 is being used) or AAAA (if IPv6 is being used) records in the given list of DNS resource records to the
     * given list of IP addresses.
     *
     * @param _ips The list of IP addresses to append to.
     * @param _rrs The list of DNS resource records to get IP addresses from.
     */
    private void addIPs( final List<InetAddress> _ips, final List<DNSResourceRecord> _rrs ) {

        Checks.required( _ips, _rrs );

        _rrs.forEach( (rr) -> {                                    // for each resource record...
            if( resolver.useIPv4() && (rr instanceof A) )          // if we're using IPv4, and we have an A record...
                _ips.add( ((A)rr).address );                       // add the IPv4 address to the list...
            else if( resolver.useIPv6() && (rr instanceof AAAA) )  // if we're using IPv6, and we have an AAAA record...
                _ips.add( ((AAAA)rr).address );                    // add the IPv6 address to the list...
        } );
    }


    public String toString() {
        return "DNSQuery: " + responseMessage.answers.size() + " answers";
    }
}
