package com.dilatush.dns.query;

import com.dilatush.dns.DNSResolver;
import com.dilatush.dns.misc.DNSResolverError;
import com.dilatush.dns.misc.DNSResolverException;
import com.dilatush.dns.misc.DNSCache;
import com.dilatush.dns.message.*;
import com.dilatush.dns.rr.*;
import com.dilatush.util.Checks;
import com.dilatush.util.ExecutorService;
import com.dilatush.util.General;
import com.dilatush.util.Outcome;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Consumer;
import java.util.logging.Logger;
import java.util.stream.Collectors;

import static com.dilatush.dns.query.DNSTransport.UDP;
import static java.util.logging.Level.FINER;
import static java.util.logging.Level.FINEST;

/**
 * Instances of this class contain the elements and state of a recursive DNS query, and provide methods that implement the resolution of that query.
 */
public class DNSRecursiveQuery extends DNSQuery {

    private static final Logger LOGGER                           = General.getLogger();
    private static final long   RECURSIVE_NAME_SERVER_TIMEOUT_MS = 5000;
    private static final int    DNS_SERVER_PORT                  = 53;

    private static final Outcome.Forge<QueryResult> queryOutcome = new Outcome.Forge<>();


    private final List<InetAddress>       nextIPs;     // IP addresses of the next name servers to query...
    private final AtomicInteger           subQueries;  // the number of sub-queries currently running...
    private final List<DNSResourceRecord> answers;     // the answers to this query...


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

        nextIPs    = new ArrayList<>();
        subQueries = new AtomicInteger();
        answers    = new ArrayList<>();

        queryLog.log("New recursive query " + question );
    }


    /**
     * Initiates a query using the given transport (UDP or TCP).  Note that a call to this method may result in several messages to DNS servers and several responses from them.
     * This may happen in the natural course of recursive resolution, if a CNAME chain needs to be resolved, if a queried DNS server doesn't respond within the timeout time, or
     * if the DNS server reports errors.
     *
     * @param _initialTransport The initial transport (UDP or TCP) to use when resolving this query.
     * @return The {@link Outcome Outcome&lt;?&gt;} of this operation.
     */
    public Outcome<?> initiate( final DNSTransport _initialTransport ) {

        Checks.required( _initialTransport, "initialTransport");

        queryLog.log("Initial query" );
        LOGGER.finer( "Initiating new recursive query - ID: " + id + ", " + question.toString() );

        initialTransport = _initialTransport;

        // we need to figure out the starting nameservers, and make agents for them...
        // we know the actual question wasn't cached, as we wouldn't have queried at all if it was - so we start looking with its parent domain,
        // unless we're already at the root domain...
        DNSDomainName searchDomain = question.qname.isRoot() ? question.qname : question.qname.parent();

        List<InetAddress> nsIPs = new ArrayList<>();

        // check our search domain, and its parents if necessary, until we have some name servers to go ask questions of...
        while( nsIPs.size() == 0 ) {

            // check the cache for name server (NS) records for the domain we're checking...
            List<DNSResourceRecord> ns = cache.get( searchDomain )
                    .stream()
                    .filter( (rr) -> rr instanceof NS )
                    .collect( Collectors.toList());

            // let's see if we have an IP address for any name servers we got...
            ns.forEach( (rr) -> addIPs( nsIPs, cache.get( ((NS)rr).nameServer ) ) );

            // if we have at least one IP address, then we're done...
            if( nsIPs.size() > 0 ) {
                queryLog.log( "Resolved '" + searchDomain.text + "' from cache" );
                break;
            }

            // no IPs yet, but if our search domain isn't the root, we can check its parent...
            if( !searchDomain.isRoot() ) {
                searchDomain = searchDomain.parent();
                continue;
            }

            queryLog.log( "No cache hits; starting from root" );

            // no IPs yet, and we're searching the root - this means one of:
            // -- we're not caching anything
            // -- the root name servers expired and were purged
            // either way, we need to read the root hints to get the root name servers...
            // so read the root hints, and if we get a null, that means we couldn't read them - very bad...
            List<DNSResourceRecord> rootHints = resolver.getRootHints();
            if( rootHints == null ) {
                queryLog.log( "Could not read root hints" );
                return queryOutcome.notOk( "Could not load root hints", new QueryResult( queryMessage, null, queryLog ) );
            }

            // add the root name server IP addresses to our list...
            addIPs( nsIPs, rootHints );

            // if we STILL have no IPs for name servers, we're dead (this really should never happen until the heat death of the universe)...
            if( nsIPs.isEmpty() ) {
                queryLog.log( "Could not find any root name server IP addresses" );
                return queryOutcome.notOk(
                        "Could not find any root name server IP addresses",
                        new DNSResolverException( "No root servers", DNSResolverError.NO_ROOT_SERVERS ),
                        new QueryResult( queryMessage, null, queryLog ) );
            }
        }

        // turn our IP addresses into agent parameters...
        nsIPs.forEach( (ip) -> serverSpecs.add( new DNSResolver.ServerSpec( RECURSIVE_NAME_SERVER_TIMEOUT_MS, 0, ip.getHostAddress(), new InetSocketAddress( ip, DNS_SERVER_PORT ) ) ) );

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

        // figure out what agent we're going to use...
        agent = new DNSServerAgent( resolver, this, nio, executor, serverSpecs.remove( 0 ) );

        LOGGER.finer( "Recursive query - ID: " + id + ", " + question.toString() + ", using " + agent.name );

        DNSMessage.Builder builder = new DNSMessage.Builder();
        builder.setOpCode( DNSOpCode.QUERY );
        builder.setRecurse( false );
        builder.setId( id & 0xFFFF );
        builder.addQuestion( question );

        queryMessage = builder.getMessage();

        queryLog.log("Sending recursive query for " + question + " to " + agent.name + " via " + transport );

        Outcome<?> sendOutcome = agent.sendQuery( queryMessage, transport );

        return sendOutcome.ok()
                ? queryOutcome.ok( new QueryResult( queryMessage, null, queryLog ) )
                : queryOutcome.notOk( sendOutcome.msg(), sendOutcome.cause() );
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
        nextIPs.clear();
        nsInfo.forEach( (rr) -> {
            if( (rr instanceof A) || (rr instanceof AAAA) ) {
                if( allNameServers.contains( rr.name.text ) ) {
                    if( resolver.useIPv4() && (rr instanceof A))
                        nextIPs.add( ((A)rr).address );
                    if( resolver.useIPv6() && (rr instanceof AAAA))
                        nextIPs.add( ((AAAA)rr).address );
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
            startNextQuery();
            return;
        }

        // we DO have unresolved name servers, so blast out sub-queries to resolve them

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


    private record AnswersAnalysis( int cnameCount, int desiredCount, int wrongCount, boolean bogus ){}

    private AnswersAnalysis analyzeAnswers() {

        final int[] cnameCount   = {0};
        final int[] desiredCount = {0};
        final int[] wrongCount   = {0};
        final boolean[] bogus = {false};
        answers.forEach( (rr) -> {
            if( rr instanceof CNAME ) {
                cnameCount[ 0 ]++;
                if( desiredCount[0] > 0 ) {
                    bogus[0] = true;
                }
            }
            else if( rr.type == question.qtype ) {
                desiredCount[0]++;
            }
            else {
                wrongCount[0]++;
                bogus[0] = true;
            }
        } );

        return new AnswersAnalysis( cnameCount[0], desiredCount[0], wrongCount[0], bogus[0] );
    }


    private void doneWithAnswers() {
        queryLog.log( "Got viable answers" );
        responseMessage = queryMessage.getSyntheticResponse( answers );
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

        LOGGER.finest( "Got some answers: " + responseMessage.answers.size() );

        // first we accumulate the answers from the message we just received with any that we've received from previous queries or sub-queries...
        answers.addAll( responseMessage.answers );

        // There are several possible scenarios here, which must be checked in the order given:
        // 1. There are zero answers, which means the query was answered but there were no results.
        // 2. There are one or more answers, and the desired type is ANY or CNAME, or they're all the desired type. In this case, we accumulate all the answers, and we're done.
        // 3. There are two or more answers, consisting of one or more CNAME records followed by one or more answers of the desired type.  In this case, we check for proper
        //    CNAME chaining, accumulate all the answers, and we're done.
        // 4. There are one or more answers, all of which are CNAME records.  In this case, the last CNAME is a referral, we accumulate all the answers, check for a CNAME
        //    loop (which is an error), and then fire off a sub-query to resolve the referral.  The results of the sub-query are evaluated exactly as the results of the
        //    first query.
        // 5. There are one or more answers which are neither CNAME records nor the desired type.  This is an error.

        // now we do a little analysis on our accumulated answers, so we can figure out what to do next...
        AnswersAnalysis aa = analyzeAnswers();

        // if we got no answers, we're done...
        if( responseMessage.answers.size() == 0 ) {
            doneWithAnswers();
            return;
        }

        // If the desired type is ANY or CNAME, or all the records are the type we want, then we're done...
        if( (question.qtype == DNSRRType.ANY) || (question.qtype == DNSRRType.CNAME) || (aa.desiredCount == answers.size())) {
            doneWithAnswers();
            return;
        }

        // if we've got one or more CNAME records followed by one or more records of our desired type, then we check for proper CNAME chaining, and we're done...
        if( (aa.cnameCount > 0) && (aa.desiredCount > 0) && !aa.bogus ) {

            // make sure our CNAME records chain properly in the order we have them, to the first record of the desired type...
            if( !isProperChaining() )
                return;

            // otherwise, send our excellent answers back...
            doneWithAnswers();
            return;
        }

        // if we have one or more CNAME records and nothing else, check for a CNAME loop, then fire a sub-query to the last (unresolved) domain...
        if( aa.cnameCount == answers.size() ) {

            // if we have a CNAME loop, that's a fatal error...
            if( !isLoopless() )
                return;

            // send off a sub-query to get the next element of the CNAME chain, or our actual answer...
            DNSDomainName nextDomain = ((CNAME)answers.get( answers.size() - 1 )).cname;
            DNSRRType nextType = question.qtype;

            LOGGER.finest( "Firing " + nextDomain.text + " " + nextType + " record sub-query " + subQueries.get() + " from query " + id );
            DNSQuestion aQuestion = new DNSQuestion( nextDomain, nextType );
            DNSRecursiveQuery recursiveQuery = new DNSRecursiveQuery( resolver, cache, nio, executor, activeQueries, aQuestion, resolver.getNextID(),
                    this::handleChainSubQuery );
            recursiveQuery.initiate( UDP );
            return;
        }

        // if we have one or more records that are neither CNAME nor our desired record type, we have an error...
        if( aa.wrongCount > 0 ) {
            doneWithProblem( "Unexpected record types in answers" );
            return;
        }

        // if we get here, we have a condition that we didn't cover in the logic above - big problem...
        doneWithProblem( "Unexpected condition in answers" );
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


    private void startNextQuery() {

        // if we have no IPs to query, we've got a problem...
        if( nextIPs.isEmpty() ) {
            handler.accept( queryOutcome.notOk( "Recursive query; no name server available for: " + question.qname.text, null,
                    new QueryResult( queryMessage, null, queryLog )) );
            activeQueries.remove( (short) id );
            return;
        }

        // turn our IP addresses into agent parameters...
        serverSpecs.clear();
        nextIPs.forEach( (ip) -> serverSpecs.add( new DNSResolver.ServerSpec( RECURSIVE_NAME_SERVER_TIMEOUT_MS, 0, ip.getHostAddress(), new InetSocketAddress( ip, DNS_SERVER_PORT ) ) ) );

        // figure out what agent we're going to use...
        agent = new DNSServerAgent( resolver, this, nio, executor, serverSpecs.remove( 0 ) );

        String logMsg = "Subsequent recursive query: " + question.toString() + ", using " + agent.name;
        LOGGER.finer( logMsg );
        queryLog.log( logMsg );

        // send the next level query...
        transport = initialTransport;
        Outcome<?> sendOutcome = agent.sendQuery( queryMessage, transport );
        if( sendOutcome.notOk() ) {
            handler.accept( queryOutcome.notOk( "Could not send query: " + sendOutcome.msg(), sendOutcome.cause(),
                    new QueryResult( queryMessage, null, queryLog )) );
            activeQueries.remove( (short) id );
        }
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

            // if we got a good result, then add any IPs we got to the next IPs list...
            DNSMessage response = _outcome.info().response();
            if( _outcome.ok() && (response != null) )
                addIPs( nextIPs, response.answers );

            // whatever happened, log the sub-query...
            queryLog.log( "Name server resolution sub-query" );
            queryLog.addSubQueryLog( _outcome.info().log() );
        }

        // decrement our counter, and if we're done, try sending the next query...
        int queryCount = subQueries.decrementAndGet();
        LOGGER.fine( "Sub-query count: " + queryCount );
        if( queryCount == 0 )
            startNextQuery();
    }


    public String toString() {
        return "DNSQuery: " + responseMessage.answers.size() + " answers";
    }
}
