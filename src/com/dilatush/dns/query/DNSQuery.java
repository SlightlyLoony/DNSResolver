package com.dilatush.dns.query;

import com.dilatush.dns.DNSResolver;
import com.dilatush.dns.DNSResolver.ServerSpec;
import com.dilatush.dns.message.DNSMessage;
import com.dilatush.dns.message.DNSQuestion;
import com.dilatush.dns.message.DNSResponseCode;
import com.dilatush.dns.misc.DNSCache;
import com.dilatush.dns.misc.DNSResolverException;
import com.dilatush.dns.misc.DNSServerException;
import com.dilatush.util.Checks;
import com.dilatush.util.ExecutorService;
import com.dilatush.util.General;
import com.dilatush.util.Outcome;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;
import java.util.logging.Level;
import java.util.logging.Logger;

import static com.dilatush.dns.message.DNSResponseCode.NAME_ERROR;
import static com.dilatush.dns.message.DNSResponseCode.OK;
import static com.dilatush.dns.misc.DNSResolverError.NETWORK;
import static com.dilatush.dns.misc.DNSResolverError.RECEIVED_MESSAGE_ON_WRONG_TRANSPORT;
import static com.dilatush.dns.query.DNSTransport.TCP;
import static com.dilatush.dns.query.DNSTransport.UDP;

/**
 * Abstract base class for query implementations.
 */
public abstract class DNSQuery {

    protected static final Outcome.Forge<QueryResult>      queryOutcome      = new Outcome.Forge<>();
    protected static final Outcome.Forge<?>                outcome           = new Outcome.Forge<>();
    private   static final Logger                          LOGGER            = General.getLogger();

    protected        final DNSResolver                     resolver;            // the resolver that owns this query...
    protected        final DNSCache                        cache;               // the resolver's cache...
    protected        final DNSNIO                          nio;                 // the resolver's network I/O implementation...
    protected        final ExecutorService                 executor;            // the resolver's executor service...
    protected        final Map<Short,DNSQuery>             activeQueries;       // the resolver's map of active queries (to ensure a reference to active queries)...
    protected        final int                             id;                  // the ID for this query...
    protected        final DNSQuestion                     question;            // the question being answered by this query...
    protected        final Consumer<Outcome<QueryResult>>  handler;             // the client's handler for this query's results...
    protected        final List<ServerSpec>                serverSpecs;         // the specs for the DNS servers available to respond to this query...
    protected        final QueryLog                        queryLog;            // the query log for this query (and any sub-queries)...

    protected              DNSServerAgent                  agent;               // the agent that communicates with a DNS server...
    protected              DNSTransport                    transport;           // the current transport in use (UDP or TCP)...
    protected              DNSTransport                    initialTransport;    // the initial transport to use (UDP or TCP)...

    protected              DNSMessage                      queryMessage;        // the query message sent to the DNS server...
    protected              DNSMessage                      responseMessage;     // the response message received from the DNS server...


    /**
     * Creates a new instance of this abstract base class using the given arguments.  Each instance of this class exists to answer a single {@link DNSQuestion}, which is one
     * of the arguments.
     *
     * @param _resolver The {@link DNSResolver} responsible for creating this query.  This reference provides the query access to some of the resolver's methods and fields.
     * @param _cache The {@link DNSCache} owned by the resolver  This reference provides access for the query to use cached resource records to resolve the query (fully or
     *               partially), and to add new resource records received from other DNS servers.
     * @param _nio The {@link DNSNIO} to use for all network I/O.  This reference is passed along to the {@link DNSServerAgent}s that need it.
     * @param _executor The {@link ExecutorService} to be used for processing received messages, to keep the load on the NIO's {@code IO Runner} thread to a minimum.
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
    protected DNSQuery( final DNSResolver _resolver, final DNSCache _cache, final DNSNIO _nio, final ExecutorService _executor,
                        final Map<Short,DNSQuery> _activeQueries, final DNSQuestion _question, final int _id,
                        final List<ServerSpec> _serverSpecs, final Consumer<Outcome<QueryResult>> _handler ) {

        Checks.required( _resolver, _cache, _nio, _executor, _activeQueries, _question, _handler );

        resolver        = _resolver;
        cache           = _cache;
        nio             = _nio;
        executor        = _executor;
        activeQueries   = _activeQueries;
        question        = _question;
        id              = _id;
        serverSpecs     = _serverSpecs;
        handler         = _handler;
        queryLog        = new QueryLog();

        // create a reference to ourselves so that we don't go "poof" when the initiate method returns...
        activeQueries.put( (short) id, this );

        queryLog.log("New query for " + question );
    }


    /**
     * Initiates a query using the given transport (UDP or TCP).  Note that a call to this method may result in several messages to DNS servers and several responses from them.
     * This may happen if a queried DNS server doesn't respond within the timeout time, or if a series of DNS servers must be queried to get the answer to the question this
     * query is trying to resolve.
     *
     * @param _initialTransport The initial transport (UDP or TCP) to use when resolving this query.
     */
    public abstract void initiate( final DNSTransport _initialTransport );


    /**
     * Called by this query's {@link DNSServerAgent} upon receipt of a message from a DNS server; it should never be called from anywhere else.  This method is always executed
     * in an {@code executor} thread.
     *
     * @param _responseMsg The {@link DNSMessage} received from a DNS server.
     * @param _transport The transport (UDP or TCP) that the message was received on.
     */
    protected void handleResponse( final DNSMessage _responseMsg, final DNSTransport _transport ) {

        Checks.required( _responseMsg, _transport );

        queryLog.log("Received response via " + _transport );
        LOGGER.finer( "Received response via " + _transport + ": " + _responseMsg.toString() );

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

        // if we made it here, it's time to actually deal with the response code we just got...
        handleResponseCode( responseMessage.responseCode );
    }


    /**
     * Resend the query using TCP, as the response from the server exceeded the maximum length of a UDP response.
     */
    protected void handleTruncatedMessage() {

        queryLog.log("UDP response was truncated; retrying with TCP" );

        // send the same query, but with TCP this time...
        transport = TCP;
        Outcome<?> sendOutcome = agent.sendQuery( queryMessage, TCP );

        // if we had a problem sending the query, that's an error...
        if( sendOutcome.notOk() ) {

            // some cleanup...
            agent.close();
            activeQueries.remove( (short) id );

            // tell the customer what happened...
            String msg = "Could not send query via TCP: " + sendOutcome.msg();
            handler.accept(
                    queryOutcome.notOk(
                            msg,
                            new DNSResolverException( msg, sendOutcome.cause(), NETWORK ),
                            new QueryResult( queryMessage, responseMessage, queryLog )
                    )
            );
        }
    }


    /**
     * Clean up after a message received on the wrong transport.
     *
     * @param _transport The transport (UDP or TCP) a message was received on.
     */
    protected void handleWrongTransport( final DNSTransport _transport ) {

        // some cleanup...
        agent.close();
        activeQueries.remove( (short) id );

        // tell the customer what happened...
        String msg = "Received message on " + _transport + ", expected it on " + transport;
        LOGGER.log( Level.WARNING, msg );
        queryLog.log( msg );
        handler.accept(
                queryOutcome.notOk(
                        msg,
                        new DNSResolverException( msg, RECEIVED_MESSAGE_ON_WRONG_TRANSPORT ),
                        new QueryResult( queryMessage, responseMessage, queryLog )
                )
        );
    }


    /**
     * Called when the response message has an "OK" response code.  Subclasses should override this method to implement their specific needs, but should call this method
     * as their first action.
     */
    protected void handleOK() {

        String logMsg = "Response was ok: "
                + responseMessage.answers.size() + " answers, "
                + responseMessage.authorities.size() + " authorities, "
                + responseMessage.additionalRecords.size() + " additional records";
        LOGGER.finest( logMsg );
        queryLog.log( logMsg );

        updateCacheFromMessage( responseMessage );
    }


    protected void updateCacheFromMessage( final DNSMessage _message ) {

        Checks.required( _message );

        // add the message's information to the cache...
        cache.add( _message.answers           );
        cache.add( _message.authorities       );
        cache.add( _message.additionalRecords );
    }


    /**
     * Analyze the response code (in a message received from a DNS server) and take the appropriate action.
     */
    protected void handleResponseCode( final DNSResponseCode _responseCode ) {

        // if we got a valid response, call the subclass' handler for that...
        if( _responseCode == OK ) {
            handleOK();
            return;
        }

        // if we got a name error, and the response is authoritative, we're done...
        else if( (_responseCode == NAME_ERROR) && responseMessage.authoritativeAnswer ) {
            handleNameError();
            return;
        }

        // otherwise, if we have more servers to try, fire off queries until one of them works, or we run out of servers to try...
        else while( !serverSpecs.isEmpty() ) {

            queryLog.log( "Response was " + _responseCode + "; trying another DNS server" );

            // resend the same query, to another server...
            //query();

        }

        // if we get here, we ran out of servers to try, so report a sad outcome and leave...
        queryLog.log("No more DNS servers to try" );

        // some cleanup...
        agent.close();
        activeQueries.remove( (short) id );

        // let the customer know...
        handler.accept( queryOutcome.notOk(
                "No more DNS servers to try; last one responded with " + _responseCode,
                new DNSServerException( _responseCode.name(), _responseCode ),
                new QueryResult( queryMessage, null, queryLog ) ) );
    }


    /**
     * We've been told authoritatively that the domain name we're querying for does not exist.  That's the end of this query; clean up and let the customer know.
     */
    private void handleNameError( ) {

        // some cleanup...
        agent.close();
        activeQueries.remove( (short) id );

        // let the customer know what happened...
        handler.accept( queryOutcome.notOk(
                "Domain does not exist: '" + question.qname + "'",
                new DNSServerException( "Domain does not exist: '" + question.qname + "'", NAME_ERROR ),
                new QueryResult( queryMessage, null, queryLog )
        ) );
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

            // query();
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
     * Return a string representation of this class.
     *
     * @return  A string representation of this class.
     */
    public String toString() {
        return "DNSQuery: " + responseMessage.answers.size() + " answers";
    }


    /**
     * Instance of this class represent one entry in the query log (one operation at a particular time, nested to a particular depth).
     */
    public static class QueryLogEntry {

        /** The message part of this query log entry. */
        public final String msg;

        /** The system time (in milliseconds) of this log entry. */
        public final long   timeMillis;

        /** The nesting depth of this log entry (0 = original query, 1 = sub-query of original query, 2 = sub-query of level 1 sub-query, etc.). */
        public final int    depth;


        /**
         * Creates a new instance of this class with the given message, a time of the current system time (in milliseconds) and a nesting depth of zero.
         *
         * @param _msg The message for this instance.
         */
        private QueryLogEntry( final String _msg ) {
            msg        = _msg;
            timeMillis = System.currentTimeMillis();
            depth      = 0;
        }


        /**
         * Creates a new instance of this class with the given parameters.
         *
         * @param _timeMillis The log entry time (a system time, in milliseconds).
         * @param _msg The message.
         * @param _depth The nesting depth.
         */
        private QueryLogEntry( final long _timeMillis, final String _msg, final int _depth ) {
            timeMillis = _timeMillis;
            msg        = _msg;
            depth      = _depth;
        }


        /**
         * Return a string representation of this log entry, with the times offset by the given start time, and indented according to the nesting level.
         *
         * @param _startTime The start time for the log.
         * @return The string representation of this log entry.
         */
        public String toString( final long _startTime ) {
            String timeStr  = String.format( "%5d", timeMillis - _startTime );  // get the right-justified time string...
            String depthStr = "| ".repeat( depth );                             // get the depth indentation and vertical lines...
            return timeStr + " " + depthStr + " " + msg + "\n";                 // put it all together for the entire entry...
        }
    }


    /**
     * Instances of this class represent the log for a query, and potentially for its sub-queries.
     */
    public static class QueryLog {
        
        private final long                startTime;  // the system time, in milliseconds, that this log was started...
        private final List<QueryLogEntry> entries;    // the entries for this log...


        /**
         * Create a new instance of this class with a start time of now, and an empty list of log entries.
         */
        public QueryLog() {
            startTime = System.currentTimeMillis();
            entries = new ArrayList<>();
        }


        /**
         * Add a new entry with the given message to this log.
         *
         * @param _msg The message for the log entry.
         */
        public void log( final String _msg ) {
            entries.add( new QueryLogEntry( _msg ) );
        }


        /**
         * Add all the entries from the given {@link QueryLog} to this query log, incrementing the nesting level for each entry.
         *
         * @param _log The {@link QueryLog} to add to this query log.
         */
        public void addSubQueryLog( final QueryLog _log ) {

            Checks.required( _log );

            _log.entries.forEach(                                                  // for each entry in the given query log...
                    (e) -> entries.add(                                            // add an entry to this log...
                            new QueryLogEntry( e.timeMillis, e.msg, e.depth + 1 )  // that is identical to the entry in the given log,
                    )                                                              // except that the nesting level is incremented...
            );
        }


        /**
         * Returns a string representation of this log: a listing of all the entries as returned by {@link QueryLogEntry#toString(long)}.
         *
         * @return A string representation of this log.
         */
        @Override
        public String toString() {
            StringBuilder sb = new StringBuilder();
            entries.forEach(
                    (e) -> sb.append( e.toString( startTime ) )
            );
            return sb.toString();
        }
    }

    /**
     * A simple record that represents the result of a query, with properties for the query message, response message, and query log.
     */
    public record QueryResult( DNSMessage query, DNSMessage response, QueryLog log ) {}
}
