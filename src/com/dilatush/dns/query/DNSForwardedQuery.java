package com.dilatush.dns.query;

import com.dilatush.dns.DNSResolver;
import com.dilatush.dns.DNSResolver.ServerSpec;
import com.dilatush.dns.message.DNSMessage;
import com.dilatush.dns.message.DNSOpCode;
import com.dilatush.dns.message.DNSQuestion;
import com.dilatush.dns.message.DNSResponseCode;
import com.dilatush.dns.misc.DNSCache;
import com.dilatush.dns.misc.DNSResolverException;
import com.dilatush.dns.misc.DNSServerException;
import com.dilatush.util.Checks;
import com.dilatush.util.ExecutorService;
import com.dilatush.util.General;
import com.dilatush.util.Outcome;
import com.dilatush.util.fsm.FSM;
import com.dilatush.util.fsm.FSMSpec;
import com.dilatush.util.fsm.FSMState;
import com.dilatush.util.fsm.FSMTransition;
import com.dilatush.util.fsm.events.FSMEvent;

import java.util.List;
import java.util.Map;
import java.util.function.Consumer;
import java.util.logging.Level;
import java.util.logging.Logger;

import static com.dilatush.dns.message.DNSResponseCode.NAME_ERROR;
import static com.dilatush.dns.message.DNSResponseCode.OK;
import static com.dilatush.dns.misc.DNSResolverError.NETWORK;
import static com.dilatush.dns.misc.DNSResolverError.TIMEOUT;
import static com.dilatush.dns.query.DNSTransport.TCP;
import static com.dilatush.dns.query.DNSTransport.UDP;

/**
 * Instances of this class contain the elements and state of a forwarded DNS query, and provide methods that implement the resolution of that query.  This implementation uses
 * a finite state machine (FSM), and the state diagram for it can be found in the Omnigraffle file {@code StateDiagrams.graffle}.
 */
public class DNSForwardedQuery extends DNSQuery {

    private static final Logger LOGGER = General.getLogger();

    private final FSM<State,Event> fsm;


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
        if( _serverSpecs.isEmpty() )
            throw new IllegalArgumentException( "No DNS servers specified for DNSForwardedQuery" );

        fsm = createFSM();

        queryLog.log("New forwarded query " + question );
    }


    /**
     * Initiates a query using the given transport (UDP or TCP).  Note that a call to this method may result in several messages to DNS servers and several responses from them.
     * This may happen if a queried DNS server doesn't respond within the timeout time, or if a series of DNS servers must be queried to get the answer to the question this
     * query is trying to resolve.
     *
     * @param _initialTransport The initial transport (UDP or TCP) to use when resolving this query.
     */
    public void initiate( final DNSTransport _initialTransport ) {

        Checks.required( _initialTransport, "initialTransport");

        initialTransport = _initialTransport;
        transport = _initialTransport;

        fsm.onEvent( fsm.event( Event.INITIATE ) );
    }


    /**
     * Called by this query's {@link DNSServerAgent} when there is a problem of some kind that occurs before a message is received and decoded, or if decoding failed; it should
     * never be called from anywhere else.  Because there's no decoded message, we don't have a lot of context for the error.  Fires a RESPONSE_PROBLEM event with a problem
     * description attached.
     *
     * @param _msg A message describing the problem.
     * @param _cause An optional {@link Throwable} cause.
     */
    protected void handleProblem( final String _msg, final Throwable _cause ) {

        queryLog.log( _msg + ((_cause != null) ? " - " + _cause.getMessage() : "") );
        LOGGER.finer( "Problem reported: " + _msg );

        // fire off our RESPONSE_PROBLEM event...
        fsm.onEvent( fsm.event( Event.RESPONSE_PROBLEM, new ProblemDescription( _msg, _cause ) ) );
    }


    /**
     * Called by this query's {@link DNSServerAgent} upon receipt of a message from a DNS server; it should never be called from anywhere else.  This method is always executed
     * in an {@code executor} thread.  Fires a DATA event with the response message attached.
     *
     * @param _responseMsg The {@link DNSMessage} received from a DNS server.
     * @param _transport The transport (UDP or TCP) that the message was received on.
     */
    protected void handleResponse( final DNSMessage _responseMsg, final DNSTransport _transport ) {

        Checks.required( _responseMsg, _transport );

        queryLog.log("Received response via " + _transport );
        LOGGER.finer( "Received response via " + _transport + ": " + _responseMsg.toString() );

        // fire off our DATA event...
        fsm.onEvent( fsm.event( Event.DATA, new ReceivedDNSMessage( _responseMsg, _transport ) ) );
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
    private void init( final FSMState<State,Event> _state ) {

        queryLog.log("Initial query" );
        LOGGER.finer( "Initiating new forwarded query - ID: " + id + ", " + question.toString() );


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
    private void shutdown( final FSMState<State,Event> _state ) {

        queryLog.log( "Shutting down query" );

        // the agent can be null, if the query was resolved from cache...
        if( agent != null)
            agent.close();

        // remove our reference, so this query can be garbage-collected...
        activeQueries.remove( (short) id );
    }



    /**
     * Event transform that checks to see if this query can be satisfied from the DNS cache.  If it can be satisfied, returns a DATA event.  Otherwise, returns a NO_CACHE event.
     *
     * @param _event The FSM event being transformed. In this case, it's always an INITIATE event.
     * @param _fsm The FSM associated with this transformation.
     * @return A DATA event if the cache satisfied the query, otherwise a NO_CACHE event.
     */
    private FSMEvent<Event> cacheCheck( final FSMEvent<Event> _event, final FSM<State,Event> _fsm  ) {

        // if we can resolve this query from the cache, pass the result on for analysis...
        DNSMessage cacheResponse = cache.resolve( queryMessage );
        if( (cacheResponse.responseCode == DNSResponseCode.OK) && (cacheResponse.answers.size() > 0) ) {
            queryLog.log( "Resolved from cache: " + question );
            return _fsm.event( Event.DATA, new ReceivedDNSMessage( cacheResponse, transport ) );  // fake the transport as the transport we expect...
        }

        // otherwise, we have to actually do a query...
        return _fsm.event( Event.NO_CACHE );
    }


    /**
     * Event transform that analyzes the response message (attached to the DATA event), returning an event according to the results of the analysis:
     * <ul>
     *     <li>TRUNCATED_UDP - if the response is truncated and was received on UDP.</li>
     *     <li>TRUNCATED_TCP - if the response is truncated and was received on TCP.</li>
     *     <li></li>
     * </ul>
     *
     * @param _event The FSM event being transformed. In this case, it's always a DATA event with an attached DNS response message.
     * @param _fsm The FSM associated with this transformation.
     * @return An event that reflects the result of the response message analysis, as described above.
     */
    private FSMEvent<Event> dataAnalysis( final FSMEvent<Event> _event, final FSM<State,Event> _fsm  ) {

        // get the information from the event...
        ReceivedDNSMessage rm = (ReceivedDNSMessage) _event.getData();
        responseMessage = rm.message;

        // if our response was truncated, we return a truncation event...
        if( responseMessage.truncated )
            return _fsm.event( (rm.transport == UDP) ? Event.TRUNCATED_UDP : Event.TRUNCATED_TCP );


        // if we got a valid response, we've got our answer...
        if( responseMessage.responseCode == OK ) {

            String logMsg = "Response was ok: "
                    + responseMessage.answers.size() + " answers, "
                    + responseMessage.authorities.size() + " authorities, "
                    + responseMessage.additionalRecords.size() + " additional records";
            LOGGER.finest( logMsg );
            queryLog.log( logMsg );

            // if we're currently in the QUERY state, then update the cache with the answer (if not, then this answer came FROM the cache)...
            if( _fsm.getStateEnum() == State.QUERY )
                updateCacheFromMessage( responseMessage );

            return _fsm.event( Event.ANSWER );
        }

        // if we got a name error, and the response is authoritative, then the name doesn't exist...
        if( responseMessage.responseCode == NAME_ERROR ) {
            queryLog.log( "Response was NAME_ERROR, so queried name does not exist" );
            return _fsm.event( Event.NAME_ERROR );
        }

        // otherwise, we got something unexpected...
        queryLog.log( "Response received was unexpected" );
        return _fsm.event( Event.UNEXPECTED );
    }


    /**
     * Event transform that analyzes events (RESPONSE_PROBLEM, TRUNCATED_TCP, UNEXPECTED), returning an event according to the results of the analysis:
     * <ul>
     *     <li>MORE_SERVERS - on any problem, if there are more DNS servers to try.</li>
     *     <li>TIMEOUT - if the query timed out and there are no more DNS servers to try.</li>
     *     <li>ERROR - if there was any error other than a timeout, and there are no more DNS servers to try.</li>
     * </ul>
     *
     * @param _event The FSM event being transformed. In this case, it could be a RESPONSE_PROBLEM, TRUNCATED_TCP, or UNEXPECTED event.
     * @param _fsm The FSM associated with this transformation.
     * @return An event that reflects the result of the response message analysis, as described above.
     */
    private FSMEvent<Event> problemAnalysis( final FSMEvent<Event> _event, final FSM<State,Event> _fsm  ) {

        // if we have more servers available, set the transport back to the initial transport and return a MORE_SERVERS event...
        if( serverSpecs.size() > 0 ) {
            queryLog.log( "Agent " + agent.name + " had " + _event.event + ", trying another agent" );
            transport = initialTransport;
            return _fsm.event( Event.MORE_SERVERS );
        }

        // if the event was a RESPONSE_PROBLEM, get the attached problem description record...
        ProblemDescription problemDescription = null;
        if( _event.event == Event.RESPONSE_PROBLEM )
            problemDescription = (ProblemDescription) _event.getData();

        // if we had a timeout, return a TIMEOUT event...
        if( (_event.event == Event.RESPONSE_PROBLEM) && (problemDescription.cause instanceof DNSTimeoutException) ) {
            queryLog.log( "Agent " + agent.name + " took too long to respond" );
            return _fsm.event( Event.TIMEOUT );
        }

        // if we had some other kind of response problem, we'll assume it's a network problem of some kind...
        if( _event.event == Event.RESPONSE_PROBLEM )
            return _fsm.event( Event.ERROR, problemDescription );

        // if we had any other kind of problem, return an ERROR event with attached problem description...
        if( _event.event == Event.TRUNCATED_TCP )
            problemDescription = new ProblemDescription( "Received truncated TCP response", null );
        else if( _event.event == Event.UNEXPECTED )
            problemDescription = new ProblemDescription( "Received unexpected query response", null );
        return _fsm.event( Event.ERROR, problemDescription );
    }


    /**
     * Transition action on TRUNCATED_UDP event that sets the transport to TCP.
     *
     * @param _transition The transition that triggered this action, in this case always QUERY::TRUNCATED_UDP.
     * @param _event The event that triggered this action.
     */
    private void requeryTCP( final FSMTransition<State,Event> _transition, FSMEvent<Event> _event ) {

        transport = TCP;

        LOGGER.finer( "Resending forwarded query to " + agent.name + " via " + transport );
        queryLog.log( "Resending forwarded query to " + agent.name + " via " + transport );

        // now actually send that query...
        Outcome<?> sendOutcome = agent.sendQuery( queryMessage, transport );

        // if we had a problem sending the query, then fire off a SEND_PROBLEM event with the attached outcome...
        if( sendOutcome.notOk() )
            _transition.fsm.onEvent( _transition.fsm.event( Event.SEND_PROBLEM, new ProblemDescription( sendOutcome.msg(), sendOutcome.cause() )) );
    }


    /**
     * Transition action on IDLE::NO_CACHE or QUERY::MORE_SERVERS, to actually send the query to the DNS server.
     *
     * @param _transition The transition that triggered this action, in this case either IDLE::NO_CACHE or QUERY::MORE_SERVERS.
     * @param _event The event that triggered this action.
     */
    private void queryServer(  final FSMTransition<State,Event> _transition, FSMEvent<Event> _event  ) {

        // get an agent...
        agent = new DNSServerAgent( resolver, this, nio, executor, serverSpecs.remove( 0 ) );

        LOGGER.finer( "Sending forwarded query to " + agent.name + " via " + transport );
        queryLog.log( "Sending forwarded query to " + agent.name + " via " + transport );

        // now actually send that query...
        Outcome<?> sendOutcome = agent.sendQuery( queryMessage, transport );

        // if we had a problem sending the query, then fire off a SEND_PROBLEM event with the attached outcome...
        if( sendOutcome.notOk() )
            _transition.fsm.onEvent( _transition.fsm.event( Event.SEND_PROBLEM, new ProblemDescription( sendOutcome.msg(), sendOutcome.cause() )) );
    }


    /**
     * Transition action on TIMEOUT event that notifies the client of a timeout.
     *
     * @param _transition The transition that triggered this action, in this case always QUERY::TIMEOUT.
     * @param _event The event that triggered this action.
     */
    private void notifyTimeout( final FSMTransition<State,Event> _transition, FSMEvent<Event> _event ) {

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
    private void notifyError( final FSMTransition<State,Event> _transition, FSMEvent<Event> _event ) {

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
     * Transition action on NAME_ERROR event that notifies the client that the queried DNS name does not exist.
     *
     * @param _transition The transition that triggered this action, in this case always QUERY::NAME_ERROR.
     * @param _event The event that triggered this action.
     */
    private void notifyNameError( final FSMTransition<State,Event> _transition, FSMEvent<Event> _event ) {

        // let the customer know what happened...
        handler.accept( queryOutcome.notOk(
                "Domain does not exist: '" + question.qname + "'",
                new DNSServerException( "Domain does not exist: '" + question.qname + "'", NAME_ERROR ),
                new QueryResult( queryMessage, null, queryLog )
        ) );
    }


    /**
     * Transition action on ANSWER event that notifies the client that an answer was obtained from a DNS server.
     *
     * @param _transition The transition that triggered this action, in this case QUERY::ANSWER (answer to a query) or IDLE::ANSWER (resolved from cache).
     * @param _event The event that triggered this action.
     */
    private void notifyAnswer( final FSMTransition<State,Event> _transition, FSMEvent<Event> _event ) {

        // send the results, and then we're done...
        handler.accept( queryOutcome.ok( new QueryResult( queryMessage, responseMessage, queryLog )) );
    }


    /**
     * Simple event listener to log events seen by the FSM.
     *
     * @param _event The event.
     */
    private void eventListener( final FSMEvent<Event> _event ) {
        Object data = _event.getData();
        String dataStr = (data == null) ? "" : ", data: " + data;
        LOGGER.log( Level.FINEST, "Event: " + _event.event + dataStr );
    }


    /**
     * Simple state change listener to log state changes within the FSM.
     *
     * @param _state The state.
     */
    private void stateChangeListener( final State _state ) {
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
        QUERY,                        // Send query to DNS server and wait for a response...
        ERROR_TERMINATION,            // Terminate the query because of an error...
        NAME_NOT_FOUND_TERMINATION,   // Terminate the query because the queried name was not found...
        ANSWER_TERMINATION            // Terminate the query because an answer for the queried name was found...
    }


    private enum Event {
        INITIATE,          // Initiate the forwarded DNS query...
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
        NAME_ERROR,        // Received an authoritative name error (queried name does not exist)...
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
        spec.setStateTerminal( State.NAME_NOT_FOUND_TERMINATION );
        spec.setStateTerminal( State.ANSWER_TERMINATION         );

        // set up our on-entry state actions...
        spec.setStateOnEntryAction( State.IDLE,                       this::init        );
        spec.setStateOnEntryAction( State.ERROR_TERMINATION,          this::shutdown    );
        spec.setStateOnEntryAction( State.NAME_NOT_FOUND_TERMINATION, this::shutdown    );
        spec.setStateOnEntryAction( State.ANSWER_TERMINATION,         this::shutdown    );

        // add all the FSM state transitions for our FSM...
        spec.addTransition( State.IDLE,           Event.NO_CACHE,            this::queryServer,      State.QUERY                       );
        spec.addTransition( State.QUERY,          Event.SEND_PROBLEM,        this::notifyError,      State.ERROR_TERMINATION           );
        spec.addTransition( State.QUERY,          Event.TIMEOUT,             this::notifyTimeout,    State.ERROR_TERMINATION           );
        spec.addTransition( State.QUERY,          Event.ERROR,               this::notifyError,      State.ERROR_TERMINATION           );
        spec.addTransition( State.IDLE,           Event.ERROR,               this::notifyError,      State.ERROR_TERMINATION           );
        spec.addTransition( State.QUERY,          Event.TRUNCATED_UDP,       this::requeryTCP,       State.QUERY                       );
        spec.addTransition( State.QUERY,          Event.MORE_SERVERS,        this::queryServer,      State.QUERY                       );
        spec.addTransition( State.QUERY,          Event.NAME_ERROR,          this::notifyNameError,  State.NAME_NOT_FOUND_TERMINATION  );
        spec.addTransition( State.QUERY,          Event.ANSWER,              this::notifyAnswer,     State.ANSWER_TERMINATION          );
        spec.addTransition( State.IDLE,           Event.ANSWER,              this::notifyAnswer,     State.ANSWER_TERMINATION          );

        // add our event transforms...
        spec.addEventTransform( Event.INITIATE,         this::cacheCheck      );
        spec.addEventTransform( Event.DATA,             this::dataAnalysis    );
        spec.addEventTransform( Event.RESPONSE_PROBLEM, this::problemAnalysis );
        spec.addEventTransform( Event.TRUNCATED_TCP,    this::problemAnalysis );
        spec.addEventTransform( Event.UNEXPECTED,       this::problemAnalysis );

        // add our listeners...
        spec.setEventListener( this::eventListener );
        spec.setStateChangeListener( this::stateChangeListener );

        // we're done with the spec, so use it to create the actual FSM and return it...
        return new FSM<>( spec );
    }

    //----------------------------------------------------------//
    //  E n d   F S M   B u i l d e r                           //
    //----------------------------------------------------------//
}
