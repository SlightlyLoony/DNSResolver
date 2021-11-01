package com.dilatush.dns.query;

import com.dilatush.dns.DNSResolver;
import com.dilatush.dns.message.*;
import com.dilatush.dns.misc.DNSCache;
import com.dilatush.dns.misc.DNSResolverError;
import com.dilatush.dns.misc.DNSResolverException;
import com.dilatush.dns.misc.DNSServerException;
import com.dilatush.dns.rr.*;
import com.dilatush.util.Checks;
import com.dilatush.util.ExecutorService;
import com.dilatush.util.General;
import com.dilatush.util.Outcome;
import com.dilatush.util.fsm.FSM;
import com.dilatush.util.fsm.FSMSpec;
import com.dilatush.util.fsm.FSMState;
import com.dilatush.util.fsm.FSMTransition;
import com.dilatush.util.fsm.events.FSMEvent;
import com.dilatush.util.ip.IPAddress;
import com.dilatush.util.ip.IPHost;
import com.dilatush.util.ip.IPv4Address;

import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Consumer;
import java.util.logging.Level;
import java.util.logging.Logger;

import static com.dilatush.dns.DNSResolver.ServerSpec;
import static com.dilatush.dns.message.DNSRRType.*;
import static com.dilatush.dns.message.DNSResponseCode.*;
import static com.dilatush.dns.misc.DNSResolverError.NETWORK;
import static com.dilatush.dns.misc.DNSResolverError.TIMEOUT;
import static com.dilatush.dns.query.DNSTransport.UDP;
import static com.dilatush.util.General.breakpoint;
import static java.util.logging.Level.*;

/**
 * Instances of this class contain the elements and state of a recursive DNS query, and provide methods that implement the resolution of that query.
 */
public class DNSRecursiveQuery extends DNSQuery {

    private static final Logger       LOGGER                           = General.getLogger();
    private static final long         RECURSIVE_NAME_SERVER_TIMEOUT_MS = 5000;
    private static final int          DNS_SERVER_PORT                  = 53;

    private static final Outcome.Forge<QueryResult> queryOutcome = new Outcome.Forge<>();


    private final FSM<State,Event>        fsm;                   // the finite state machine (FSM) for this query...


    private final List<IPAddress>         nextNameServerIPs;     // IP addresses of the next name servers to query...
    private final AtomicInteger           subQueries;            // the number of sub-queries currently running...
    private final List<DNSResourceRecord> answers;               // the answers to this query...

    private       List<IPHost>            nameServers;           // Hostnames and IPs of name servers we can query (IP is wildcard if unknown)...




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
        super( _resolver, _cache, _nio, _executor, _activeQueries, _question, _id, _handler );

        nameServers       = new ArrayList<>();
        fsm               = createFSM();


        nextNameServerIPs = new ArrayList<>();
        subQueries        = new AtomicInteger();
        answers           = new ArrayList<>();

        queryLog.log("New recursive query " + question );
    }


    /**
     * Initiates a query using UDP transport.  Note that a call to this method may result in several messages to DNS servers and several responses from them.
     * This may happen if a queried DNS server doesn't respond within the timeout time, or if a series of DNS servers must be queried to get the answer to the question this
     * query is trying to resolve.
     */
    public void initiate() {

        queryLog.log("Initial query" );
        LOGGER.finer( "Initiating new recursive query - ID: " + id + ", " + question.toString() );

        // kick off our finite state machine...
        fsm.onEvent( fsm.event( Event.INITIATE ) );
    }


    /**
     * Analyzes the given {@link DNSMessage}, using the authorities as a source of name server host names, and the additional records as a source of IP addresses.  Builds a list
     * of {@link IPHost} records.  The first elements in the list are those with IP addresses (if there are any), in the order they appeared in the authorities.  Subsequent
     * elements are those without IP addresses, in the order they appeared in authorities.  The resolver's configuration for IP version (v4 or v6) are honored, and if both versions
     * are used and provided, the v4 address has precedence.
     *
     * @param _responseMessage The response message to obtain name servers from.
     * @return The {@link List List&lt;IPHost&gt;} with the results.
     */
    private List<IPHost> getNameServers( final DNSMessage _responseMessage ) {

        Checks.required( _responseMessage );

        // make a map of name server host names -> IP addresses, so we can associate those we have...
        Map<String,IPAddress> nsMap = new HashMap<>();

        // iterate over our authorities, populating the map and assigning IPv4 wildcard addresses to indicate that we don't yet have an actual IP address...
        _responseMessage.authorities.stream()
                .filter( (rr) -> rr instanceof NS )
                .map( (rr) -> (NS)rr )
                .forEach( (ns) -> nsMap.put( ns.nameServer.text, IPv4Address.WILDCARD ) );

        // if our resolver uses IPv4 addresses, iterate over our additional records to get the IPv4 addresses, matching them up with name servers...
        if( resolver.useIPv4() ) {
            _responseMessage.additionalRecords.stream()
                    .filter( (rr) -> rr instanceof A )
                    .map( (rr) -> (A)rr )
                    .forEach( (a) -> {
                        if( nsMap.containsKey( a.name.text ) )
                            nsMap.put( a.name.text, a.address );
                    } );
        }

        // if our resolver uses IPv6 addresses, iterate over our additional records to get the IPv6 addresses, matching them up with name servers that have no IP address yet...
        if( resolver.useIPv6() ) {
            _responseMessage.additionalRecords.stream()
                    .filter( (rr) -> rr instanceof AAAA )
                    .map( (rr) -> (AAAA)rr )
                    .forEach( (aaaa) -> {
                        if( nsMap.get( aaaa.name.text ) == IPv4Address.WILDCARD )
                            nsMap.put( aaaa.name.text, aaaa.address );
                    } );
        }

        // now build our list of results, making two passes to get first those name servers with IP addresses, and then those without...
        List<IPHost> results = new ArrayList<>( _responseMessage.authorities.size() );
        _responseMessage.authorities.stream()
                .filter( (rr) -> rr instanceof NS )
                .map( (rr) -> (NS)rr )
                .filter( (ns) -> nsMap.get( ns.nameServer.text ) != IPv4Address.WILDCARD )
                .forEach( (ns) -> results.add( IPHost.create( ns.nameServer.text, nsMap.get( ns.nameServer.text ) ).info() ));
        _responseMessage.authorities.stream()
                .filter( (rr) -> rr instanceof NS )
                .map( (rr) -> (NS)rr )
                .filter( (ns) -> nsMap.get( ns.nameServer.text ) == IPv4Address.WILDCARD )
                .forEach( (ns) -> results.add( IPHost.create( ns.nameServer.text ).info() ));

        // we're done...
        return results;
    }


    /**
     * Invoked by CNAME subqueries, to provide the result of the subquery.
     *
     * @param _outcome The {@link Outcome Outcome&lt;QueryResult&gt;} of the subquery.
     */
    private void handleCNAMESubqueryResponse( final Outcome<QueryResult> _outcome ) {

        // get the query result...
        QueryResult qr = _outcome.info();

        // if the outcome was not ok, then we have a failed query...
        if( _outcome.notOk() ) {

            // take care of the logging...
            queryLog.log( "Bad outcome on CNAME subquery: " + _outcome.msg() );
            activeQueries.remove( (short) id );
            queryLog.log( "CNAME sub-query: " + qr.query().questions.get( 0 ).toString() );
            queryLog.addSubQueryLog( qr.log() );

            // fire a CNAME_ERROR event with a problem description...
            fsm.event( Event.CNAME_ERROR, new ProblemDescription( _outcome.msg(), _outcome.cause() ) );
            return;
        }

        // take care of the logging...
        queryLog.log( "CNAME sub-query: " + qr.query().questions.get( 0 ).toString() );
        queryLog.addSubQueryLog( _outcome.info().log() );

        // fire a GOT_ANSWER event with attached message...
        fsm.event( Event.GOT_ANSWER, qr.response() );
    }


    private record ProblemDescription( String msg, Throwable cause ){}

    private record ReceivedDNSMessage( DNSMessage message, DNSTransport transport ){}



    //----------------------------------------------------------//
    //  B e g i n   F i n i t e   S t a t e   M a c h i n e     //
    //----------------------------------------------------------//


    /**
     * Invoked on entry to the IDLE state, which occurs on the first event received by the FSM.
     *
     * @param _state The state being entered, in this case always IDLE.
     */
    private void init( final FSMState<State, Event> _state ) {

        queryLog.log("Initial query" );
        LOGGER.finer( "Initiating new recursive query - ID: " + id + ", " + question.toString() );


        // build the query message we need to query the cache, or send to the DNS server...
        DNSMessage.Builder builder = new DNSMessage.Builder();
        builder
                .setOpCode(   DNSOpCode.QUERY )
                .setRecurse(  true            )
                .setId(       id & 0xFFFF     )
                .addQuestion( question );
        queryMessage = builder.getMessage();
    }


    /**
     * Invoked on entry to all terminal states, to shut down the query.
     *
     * @param _state The state being entered.
     */
    private void shutdown( final FSMState<State, Event> _state ) {

        queryLog.log( "Shutting down query" );

        // the agent can be null, if the query was resolved from cache...
        if( agent != null)
            agent.close();

        // remove our reference, so this query can be garbage-collected...
        activeQueries.remove( (short) id );
    }


    /**
     * Event transform that checks to see if this query can be satisfied from the DNS cache.
     *
     * @param _event The FSM event being transformed. In this case, it's either a NS_ANSWER or an INITIATE event.
     * @param _fsm The FSM associated with this transformation.
     * @return An event reflecting the analysis of the cache resolution.
     */
    private FSMEvent<Event> cacheCheck( final FSMEvent<Event> _event, final FSM<State, Event> _fsm  ) {

        // if our incoming event has an attached DNSMessage, inspect it; it may have a name error, or it may have updates to the cache...
        Object attachment = _event.getData();
        if( attachment instanceof DNSMessage msg ) {

            // if the message shows a name error, return a NAME_ERROR event...
            if( msg.responseCode == NAME_ERROR )
                return _fsm.event( Event.NAME_ERROR );

            // otherwise, update the DNS cache...
            updateCacheFromMessage( msg );
        }

        // try to resolve the query through the cache...
        DNSMessage cacheResponse = cache.resolve( queryMessage );

        queryLog.log( "Resolved from cache: response code: " + cacheResponse.responseCode + ", " + cacheResponse.answers.size() + " answers, " + cacheResponse.authorities.size()
                + " authorities, " + cacheResponse.additionalRecords.size() + " additional records" );

        // if the response code is SERVER_FAILURE, then we couldn't get the root hints; return a NO_ROOT_HINTS event...
        if( cacheResponse.responseCode == SERVER_FAILURE ) {
            String msg = "Could not get root hints from cache";
            LOGGER.log( SEVERE, msg );
            queryLog.log( msg );
            return _fsm.event( Event.NO_ROOT_HINTS );
        }

        // if the response code is FORMAT_ERROR, then the query is malformed; return a MALFORMED_QUERY event...
        if( cacheResponse.responseCode == FORMAT_ERROR ) {
            String msg = "Query is malformed";
            LOGGER.log( SEVERE, msg );
            queryLog.log( msg );
            return _fsm.event( Event.MALFORMED_QUERY );
        }

        // if the response code is OK, and we have some answers; return a GOT_ANSWER event with attached response...
        if( (cacheResponse.responseCode == OK) && (cacheResponse.answers.size() > 0) ) {
            String msg = "Resolved from cache: " + question;
            queryLog.log( msg );
            LOGGER.log( FINER, msg );
            return _fsm.event( Event.GOT_ANSWER, cacheResponse );
        }

        // if we didn't get the expected sort of answer, then we have a problem; return a NO_NAME_SERVERS event...
        if( (cacheResponse.responseCode != OK) || (cacheResponse.authorities.size() == 0) ) {
            String msg = "No name servers available for resolving " + cacheResponse.getQuestion().qclass.text;
            queryLog.log( msg );
            LOGGER.log( FINE, msg );
            return _fsm.event( Event.NO_NAME_SERVERS );
        }

        // get our list of name servers and their IP addresses...
        nameServers = getNameServers( cacheResponse );

        // return a QUERY_NS event...
        return _fsm.event( Event.QUERY_NS );
    }


    /**
     * Event transform that checks to see we have a complete answer, or if we need to resolve a CNAME alias.
     *
     * @param _event The FSM event being transformed. In this case, it's always a GOT_ANSWER event with an attached {@link DNSMessage}.
     * @param _fsm The FSM associated with this transformation.
     * @return A FINAL_ANSWER or a QUERY_CNAME event.
     */
    private FSMEvent<Event> answerCheck( final FSMEvent<Event> _event, final FSM<State, Event> _fsm  ) {

        // get the DNS message attached to our event...
        DNSMessage msg = (DNSMessage) _event.getData();

        // if we have a single answer, it's a CNAME record, and our query was neither a CNAME nor an ANY query, then we need to follow the CNAME trail...
        if( (msg.answers.size() == 1) && (msg.answers.get( 0 ) instanceof CNAME cname) && !((question.qtype == CNAME) || (question.qtype == ANY)) ) {

            // save the CNAME in our accumulated answers...
            answers.add( cname );

            // return a QUERY_CNAME event with attached name to resolve...
            return _fsm.event( Event.QUERY_CNAME, cname.cname.text );
        }

        // otherwise, we must have the final answer - so save the answers and return a FINAL_ANSWER event...
        answers.addAll( msg.answers );
        return _fsm.event( Event.FINAL_ANSWER );
    }


    /**
     * Event transform that checks to see we have a complete answer, or if we need to resolve a CNAME alias.
     *
     * @param _event The FSM event being transformed. In this case, it's always a GOT_ANSWER event with an attached {@link DNSMessage}.
     * @param _fsm The FSM associated with this transformation.
     * @return A FINAL_ANSWER or a QUERY_CNAME event.
     */
    private FSMEvent<Event> ensureNameServer( final FSMEvent<Event> _event, final FSM<State, Event> _fsm  ) {

        // get the DNS message attached to our event...
        DNSMessage msg = (DNSMessage) _event.getData();

        // if we have a single answer, it's a CNAME record, and our query was neither a CNAME nor an ANY query, then we need to follow the CNAME trail...
        if( (msg.answers.size() == 1) && (msg.answers.get( 0 ) instanceof CNAME cname) && !((question.qtype == CNAME) || (question.qtype == ANY)) ) {

            // save the CNAME in our accumulated answers...
            answers.add( cname );

            // return a QUERY_CNAME event with attached name to resolve...
            return _fsm.event( Event.QUERY_CNAME, cname.cname.text );
        }

        // otherwise, we must have the final answer - so save the answers and return a FINAL_ANSWER event...
        answers.addAll( msg.answers );
        return _fsm.event( Event.FINAL_ANSWER );
    }


    /**
     * Transition action on IDLE::QUERY_CNAME or QUERY_NS::QUERY_CNAME, to initiate the sub-query.  The QUERY_CNAME event has a string attached with the
     * canonical name to query.
     *
     * @param _transition The transition that triggered this action, in this case either IDLE::QUERY_CNAME or QUERY_NS::QUERY_CNAME.
     * @param _event The event that triggered this action, in this case always QUERY_CNAME.
     */
    private void initiateCNAMESubquery( final FSMTransition<State, Event> _transition, FSMEvent<Event> _event  ) {

        // send off a sub-query to get the next element of the CNAME chain, or our actual answer...
        String canonicalName = (String) _event.getData();
        DNSDomainName nextDomain = DNSDomainName.fromString( canonicalName ).info();
        DNSRRType nextType = question.qtype;

        String msg = "Firing " + nextDomain.text + " " + nextType + " record sub-query " + subQueries.get() + " from query " + id;
        LOGGER.finest( msg );
        queryLog.log( msg );
        DNSQuestion cnameSubqueryQuestion = new DNSQuestion( nextDomain, nextType );
        DNSRecursiveQuery recursiveQuery = new DNSRecursiveQuery( resolver, cache, nio, executor, activeQueries, cnameSubqueryQuestion, resolver.getNextID(),
                this::handleCNAMESubqueryResponse );
        recursiveQuery.initiate();
    }


    /**
     * Transition action on IDLE::FINAL_ANSWER, QUERY_NS::FINAL_ANSWER, or SUB_QUERY_CNAME::FINAL_ANSWER that notifies the client that an answer was obtained from a DNS server.
     *
     * @param _transition The transition that triggered this action.
     * @param _event The event that triggered this action.
     */
    private void notifyAnswer( final FSMTransition<State, Event> _transition, FSMEvent<Event> _event ) {

        // send the results, and then we're done...
        handler.accept( queryOutcome.ok( new QueryResult( queryMessage, responseMessage, queryLog )) );
    }


    /**
     * Transition action on QUERY_NS::NAME_ERROR that notifies the client that the queried DNS name does not exist.
     *
     * @param _transition The transition that triggered this action, in this case always QUERY_NS::NAME_ERROR.
     * @param _event The event that triggered this action.
     */
    private void notifyNameError( final FSMTransition<State, Event> _transition, FSMEvent<Event> _event ) {

        // let the customer know what happened...
        handler.accept( queryOutcome.notOk(
                "Domain does not exist: '" + question.qname + "'",
                new DNSServerException( "Domain does not exist: '" + question.qname + "'", NAME_ERROR ),
                new QueryResult( queryMessage, null, queryLog )
        ) );
    }


    /**
     * Transition action on TIMEOUT event that notifies the client of a timeout.
     *
     * @param _transition The transition that triggered this action, in this case always QUERY::TIMEOUT.
     * @param _event The event that triggered this action.
     */
    private void notifyTimeout( final FSMTransition<State, Event> _transition, FSMEvent<Event> _event ) {

        handler.accept(
                queryOutcome.notOk(
                        "DNS query timed out",
                        new DNSResolverException( "DNS query timed out", null, TIMEOUT ),
                        new QueryResult( queryMessage, null, queryLog )
                )
        );
    }


    /**
     * Transition action on ERROR event that notifies the client of an error.
     *
     * @param _transition The transition that triggered this action, in this case always QUERY::ERROR.
     * @param _event The event that triggered this action.
     */
    private void notifyError( final FSMTransition<State, Event> _transition, FSMEvent<Event> _event ) {

        // get the problem description...
        ProblemDescription problemDescription = (ProblemDescription) _event.getData();

        handler.accept(
                queryOutcome.notOk(
                        problemDescription.msg,
                        new DNSResolverException( problemDescription.msg, problemDescription.cause, NETWORK ),
                        new QueryResult( queryMessage, null, queryLog )
                )
        );
    }


    /**
     * Simple event listener to log events seen by the FSM.
     *
     * @param _event The event.
     */
    private void eventListener( final FSMEvent<Event> _event ) {

        // note the event in the query log...
        queryLog.log( "Event: " + _event.event );

        // and maybe in the log...
        if( LOGGER.isLoggable( Level.FINEST )) {
            Object data = _event.getData();
            String dataStr = (data == null) ? "" : ", data: " + data;
            LOGGER.log( Level.FINEST, "Event: " + _event.event + dataStr );
        }
    }


    /**
     * Simple state change listener to log state changes within the FSM.
     *
     * @param _state The state.
     */
    private void stateChangeListener( final State _state ) {

        // note the state change in the query log...
        queryLog.log( "To state: " + _state );

        // and maybe in the log...
        LOGGER.log( Level.FINEST, "State changed to: " + _state );
    }


    //----------------------------------------------------------//
    //  E n d   F i n i t e   S t a t e   M a c h i n e         //
    //----------------------------------------------------------//


    //----------------------------------------------------------//
    //  B e g i n   F S M   B u i l d e r                       //
    //----------------------------------------------------------//

    private enum State {
        IDLE,                         // FSM constructed, but nothing has happened...
        SUB_QUERY_NS_IP,              // Send sub-query for name server IP address and wait for a response...
        SUB_QUERY_CNAME,              // Send sub-query for CNAME resolution and wait for a responwe...
        QUERY_NS,                     // Send query to DNS server and wait for a response...
        ERROR_TERMINATION,            // Terminate the query because of an error...
        ANSWER_TERMINATION            // Terminate the query because an answer for the queried name was found...
    }


    private enum Event {
        INITIATE,          // Initiate the recursive DNS query...
        NO_ROOT_HINTS,     // Tried to resolve from cache, but couldn't even get root hints...
        MALFORMED_QUERY,   // Tried to resolve from cache, but the cache didn't understand the query...
        GOT_ANSWER,        // Tried to resolve from cache, and got some answers, but what sort of answer isn't known yet...
        NO_NAME_SERVERS,   // Tried to resolve from cache, got no answers and also no name servers to query...
        INITIATE_NS_QUERY, // Kick off the process of querying a name server...
        QUERY_NS_FAIL,     // Query of name server failed...
        QUERY_NS,          // Query name server...
        SUBQUERY_NS_IP,    // Sub-query for a name server's IP address...
        GOT_NS_IP,         // Got an IP address for a name server...
        NO_NS_IP,          // Failed to get an IP address for a name server...
        NS_ANSWER,         // Got an answer from a name server query...
        NAME_ERROR,        // Received an authoritative name error (queried name does not exist)...
        QUERY_CNAME,       // Sub-query the canonical name...
        FINAL_ANSWER,      // Got the final answer...
        CNAME_ERROR,       // Got an error when querying for CNAME resolution...



        NO_CACHE,          // The query could not be resolved from the cache...
        DATA,              // Received data from the queried DNS server (or the cache)...
        RESPONSE_PROBLEM,  // Problem occurred with the response from a queried DNS server (timeout or an error of some kind)...
        SEND_PROBLEM,      // Problem occurred when sending a query to a DNS server...
        MORE_SERVERS,      // There are more DNS servers we can try to query...
        TIMEOUT,           // Timed out while waiting for a response from a DNS server...
        ERROR,             // There was an error when querying a DNS server...
        TRUNCATED_UDP,     // Received data via UDP, and response was truncated...
        TRUNCATED_TCP,     // Received data via TCP, and response was truncated...
        UNEXPECTED,        // Received a response that did not fit the expected patterns...
        ANSWER             // Received an authoritative answer to the DNS query...
    }


    /**
     * Create and return the engine controller FSM.
     *
     * @return the FSM created
     */
    private FSM<State, Event> createFSM() {

        // create our FSM specification with the initial state and an example event...
        FSMSpec<State, Event> spec = new FSMSpec<>( State.IDLE, Event.DATA );

        // mark our terminal states...
        spec.setStateTerminal( State.ERROR_TERMINATION          );
        spec.setStateTerminal( State.ANSWER_TERMINATION         );

        // set up our on-entry state actions...
        spec.setStateOnEntryAction( State.IDLE,                       this::init        );
        spec.setStateOnEntryAction( State.ERROR_TERMINATION,          this::shutdown    );
        spec.setStateOnEntryAction( State.ANSWER_TERMINATION,         this::shutdown    );

        // add all the FSM state transitions for our FSM...
        spec.addTransition( State.IDLE,            Event.QUERY_CNAME,         this::initiateCNAMESubquery,      State.SUB_QUERY_CNAME      );
        spec.addTransition( State.QUERY_NS,        Event.QUERY_CNAME,         this::initiateCNAMESubquery,      State.SUB_QUERY_CNAME      );
        spec.addTransition( State.SUB_QUERY_CNAME, Event.QUERY_CNAME,         this::initiateCNAMESubquery,      State.SUB_QUERY_CNAME      );
        spec.addTransition( State.IDLE,            Event.FINAL_ANSWER,        this::notifyAnswer,               State.ANSWER_TERMINATION   );
        spec.addTransition( State.QUERY_NS,        Event.FINAL_ANSWER,        this::notifyAnswer,               State.ANSWER_TERMINATION   );
        spec.addTransition( State.SUB_QUERY_CNAME, Event.FINAL_ANSWER,        this::notifyAnswer,               State.ANSWER_TERMINATION   );
        spec.addTransition( State.QUERY_NS,        Event.NAME_ERROR,          this::notifyNameError,            State.ERROR_TERMINATION    );

        // add our event transforms...
        spec.addEventTransform( Event.INITIATE,         this::cacheCheck      );
        spec.addEventTransform( Event.NS_ANSWER,        this::cacheCheck      );
        spec.addEventTransform( Event.GOT_ANSWER,       this::answerCheck     );

        // add our listeners...
        spec.setEventListener( this::eventListener );
        spec.setStateChangeListener( this::stateChangeListener );

        // we're done with the spec, so use it to create the actual FSM and return it...
        return new FSM<>( spec );
    }

    //----------------------------------------------------------//
    //  E n d   F S M   B u i l d e r                           //
    //----------------------------------------------------------//


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

        transport = UDP;


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
               .forEach( (rr) -> nameServerIPMap.put( ((NS)rr).nameServer.text, IPv4Address.WILDCARD )
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
               .filter( (entry) -> { return entry.getValue() == IPv4Address.WILDCARD; } )    // the == works here, because we're looking for occurrences of the same instance...
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
                       IPAddress nsip = (iprr instanceof A) ? ((A)iprr).address : ((AAAA)iprr).address;
                       entry.setValue( nsip );
                   }
               } );

       // we now have one or more name servers, with zero or more associated IP addresses - time to see if we have enough, or if we need to sub-query...
       long ipCount = nameServerIPMap.values().stream().filter( (ip) -> ip != IPv4Address.WILDCARD ).count();  // count the associated IPs...
       return (ipCount == nameServerIPMap.size()) || (ipCount >= 1);  // TODO: what should this number be???
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
               .filter( (entry) -> entry.getValue() == IPv4Address.WILDCARD )
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
                       recursiveQuery.initiate();
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
                       recursiveQuery.initiate();
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

       // if it's OK, authoritative, and we have at least one answer, then we've finished our recursive journey, and it's time to give our caller what he asked for...
       else if( (responseMessage.responseCode == OK) && (responseMessage.answers.size() > 0) && responseMessage.authoritativeAnswer ) {

           updateCacheFromMessage( responseMessage );
           handler.accept( queryOutcome.ok( new QueryResult( queryMessage, responseMessage, queryLog )) );
       }

       // if it's a NAME_ERROR, and authoritative, then it's time to disappoint our caller...
       else if( (responseMessage.responseCode == NAME_ERROR) && responseMessage.authoritativeAnswer ) {
// TODO: complete
       }

       // otherwise, it's something we don't understand, so log it and tell our caller we've failed...
       else {
// TODO: complete
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
                recursiveQuery.initiate();
            }

            // fire off the query for the AAAA record...
            if( resolver.useIPv6() ) {
                subQueries.incrementAndGet();
                LOGGER.finest( "Firing " + nsDomainName.text + " AAAA record sub-query " + subQueries.get() + " from query " + id );
                DNSQuestion aQuestion = new DNSQuestion( nsDomainName, DNSRRType.AAAA );
                DNSRecursiveQuery recursiveQuery = new DNSRecursiveQuery( resolver, cache, nio, executor, activeQueries, aQuestion, resolver.getNextID(), this::handleNSResolutionSubQuery );
                recursiveQuery.initiate();
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
    private void addIPs( final List<IPAddress> _ips, final List<DNSResourceRecord> _rrs ) {

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
