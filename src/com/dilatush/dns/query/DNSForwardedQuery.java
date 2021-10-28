package com.dilatush.dns.query;

import com.dilatush.dns.DNSResolver;
import com.dilatush.dns.DNSResolver.ServerSpec;
import com.dilatush.dns.message.DNSMessage;
import com.dilatush.dns.message.DNSOpCode;
import com.dilatush.dns.message.DNSQuestion;
import com.dilatush.dns.message.DNSResponseCode;
import com.dilatush.dns.misc.DNSCache;
import com.dilatush.dns.misc.DNSResolverException;
import com.dilatush.util.Checks;
import com.dilatush.util.ExecutorService;
import com.dilatush.util.General;
import com.dilatush.util.Outcome;

import java.util.List;
import java.util.Map;
import java.util.function.Consumer;
import java.util.logging.Logger;

import static com.dilatush.dns.misc.DNSResolverError.NETWORK;

/**
 * Instances of this class contain the elements and state of a forwarded DNS query, and provide methods that implement the resolution of that query.
 */
public class DNSForwardedQuery extends DNSQuery {

    // TODO: make FSM lightweight - no dispatch thread, no scheduler...
    // TODO: move init code to IDLE on-entry action...

    private static final Logger LOGGER = General.getLogger();


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
     * @param _serverSpecs The {@link List List&lt;ServerSpec&gt;} of the parameters used to create {@link DNSServerAgent} instances that can query other DNS servers.  Note that
     *                     for forwarded queries this list is supplied by the resolver, but for recursive queries it is generated in the course of making the queries.
     * @param _handler The {@link Consumer Consumer&lt;Outcome&lt;QueryResult&gt;&gt;} handler that will be called when the query is completed.  Note that the handler is called
     *                 either for success or failure.
     */
    public DNSForwardedQuery( final DNSResolver _resolver, final DNSCache _cache, final DNSNIO _nio, final ExecutorService _executor,
                              final Map<Short,DNSQuery> _activeQueries, final DNSQuestion _question, final int _id,
                              final List<ServerSpec> _serverSpecs, final Consumer<Outcome<QueryResult>> _handler ) {
        super( _resolver, _cache, _nio, _executor, _activeQueries, _question, _id, _serverSpecs, _handler );

        Checks.required( _serverSpecs );

        queryLog.log("New forwarded query " + question );
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
        LOGGER.finer( "Initiating new forwarded query - ID: " + id + ", " + question.toString() );

        initialTransport = _initialTransport;

        // if we have no agents, then revert to a recursive query...
        if( serverSpecs.isEmpty() ) {
            DNSQuery recursiveQuery = new DNSRecursiveQuery( resolver, cache, nio, executor, activeQueries, question, id, handler );
            return recursiveQuery.initiate( _initialTransport );
        }

        // we're set up; now it's time to actually go make the query...
        return query();
    }


    /**
     * Send the query to the DNS server, returning an {@link Outcome Outcome&lt;?&gt;} with the result.  Generally the outcome will be "not ok" only if there is some problem
     * with the network or connection to a specific DNS server.  This method may be called repeatedly during the resolution of a single query.  It is always called once when the
     * query is initiated.  It may be called again if the queried DNS server fails to respond, or responds with an error, or (during a recursive query) to query for authorities
     * and name server IP address resolution.
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
        LOGGER.finer( "forwarded query - ID: " + id + ", " + question.toString() + ", using " + agent.name );

        // build the query message we need to send to the DNS server...
        DNSMessage.Builder builder = new DNSMessage.Builder();
        builder
            .setOpCode(   DNSOpCode.QUERY )
            .setRecurse(  true            )
            .setId(       id & 0xFFFF     )
            .addQuestion( question );
        queryMessage = builder.getMessage();

        // if we can resolve this query from the cache, we're done...
        DNSMessage cacheResponse = cache.resolve( queryMessage );
        if( (cacheResponse.responseCode == DNSResponseCode.OK) && (cacheResponse.answers.size() > 0) ) {
            queryLog.log( "Resolved from cache: " + question );
            handler.accept( queryOutcome.ok( new QueryResult( queryMessage, cacheResponse, queryLog ) ) );
            return outcome.ok();
        }

        queryLog.log("Sending forwarded query to " + agent.name + " via " + transport );

        // now actually send that query...
        Outcome<?> sendOutcome = agent.sendQuery( queryMessage, transport );

        return sendOutcome.ok()
                ? queryOutcome.ok()
                : queryOutcome.notOk( sendOutcome.msg(), new DNSResolverException( "Problem sending message", sendOutcome.cause(), NETWORK ) );
    }


    /**
     * Called when the response message has an "OK" response code.  Adds the results (answers, authorities, and additional records) to the cache, then sends an "ok" outcome with
     * the response message to the client's handler.
     */
    protected void handleOK() {
        super.handleOK();

        // send the results, and then we're done...
        handler.accept( queryOutcome.ok( new QueryResult( queryMessage, responseMessage, queryLog )) );
    }


    /**
     * Returns a string representation of this instance.
     *
     * @return A string representation of this instance.
     */
    public String toString() {
        return "DNSQuery: " + responseMessage.answers.size() + " answers";
    }
}
