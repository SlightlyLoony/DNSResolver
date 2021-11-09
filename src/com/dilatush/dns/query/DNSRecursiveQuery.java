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

import java.net.InetSocketAddress;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Consumer;
import java.util.logging.Level;
import java.util.logging.Logger;

import static com.dilatush.dns.DNSResolver.ServerSpec;
import static com.dilatush.dns.message.DNSRRType.ANY;
import static com.dilatush.dns.message.DNSRRType.CNAME;
import static com.dilatush.dns.message.DNSResponseCode.*;
import static com.dilatush.dns.misc.DNSResolverError.*;
import static com.dilatush.dns.query.DNSTransport.TCP;
import static com.dilatush.dns.query.DNSTransport.UDP;
import static java.util.logging.Level.*;

// TODO: how do I make ANY queries work, when they fail from the cache?

/**
 * Instances of this class contain the elements and state of a recursive DNS query, and provide methods that implement the resolution of that query.
 */
public class DNSRecursiveQuery extends DNSQuery {

    private static final Logger       LOGGER                           = General.getLogger();
    private static final long         RECURSIVE_NAME_SERVER_TIMEOUT_MS = 2000;
    private static final int          DNS_SERVER_PORT                  = 53;

    private static final Outcome.Forge<QueryResult> queryOutcome = new Outcome.Forge<>();


    private final FSM<State,Event>        fsm;                   // the finite state machine (FSM) for this query...


    private final AtomicInteger           nsIPsubQueries;        // the number of name server IP sub-queries currently running...
    private final List<IPAddress>         nsIPv4Addresses;       // IPv4 addresses that we got when sub-querying for name server IP addresses...
    private final List<IPAddress>         nsIPv6Addresses;       // IPv6 addresses that we got when sub-querying for name server IP addresses...

    @SuppressWarnings( "MismatchedQueryAndUpdateOfCollection" )
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


        nsIPsubQueries    = new AtomicInteger();
        nsIPv4Addresses   = new ArrayList<>();
        nsIPv6Addresses   = new ArrayList<>();
        answers           = new ArrayList<>();

        queryLog.log("New recursive query " + question );
    }


    /**
     * Initiates a query using UDP transport.  Note that a call to this method may result in several messages to DNS servers and several responses from them.
     * This may happen if a queried DNS server doesn't respond within the timeout time, or if a series of DNS servers must be queried to get the answer to the question this
     * query is trying to resolve.
     */
    public void initiate() {

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
            String msg = "Bad outcome on CNAME subquery: " + _outcome.msg();
            queryLog.log( msg );
            queryLog.addSubQueryLog( qr.log() );
            LOGGER.finer( msg );

            // fire a CNAME_ERROR event with a problem description...
            fsm.onEvent( fsm.event( Event.CNAME_ERROR, new ProblemDescription( _outcome.msg(), _outcome.cause() ) ) );
            return;
        }

        // take care of the logging...
        String msg = "CNAME sub-query: " + qr.query().questions.get( 0 ).toString();
        queryLog.log( msg );
        queryLog.addSubQueryLog( _outcome.info().log() );
        LOGGER.finer( msg );

        // fire a GOT_ANSWER event with attached message...
        fsm.onEvent( fsm.event( Event.GOT_ANSWER, qr.response() ) );
    }


    /**
     * Invoked by NS IP subqueries, to provide the result of the subquery.
     *
     * @param _outcome The {@link Outcome Outcome&lt;QueryResult&gt;} of the subquery.
     */
    private void handleNSIPSubqueryResponse( final Outcome<QueryResult> _outcome ) {

        // get the query result...
        QueryResult qr = _outcome.info();

        // if the outcome was ok, extract any IP addresses we got and squirrel them away...
        if( _outcome.ok() ) {

            // iterate over the answers to extract any IP addresses...
            qr.response().answers                                // iterate over all the answers...
                    .forEach( (rr) -> {
                        if( rr instanceof A a )                  // if it's an A record, extract the IPv4 address...
                            nsIPv4Addresses.add( a.address );
                        if( rr instanceof AAAA aaaa )            // if it's an AAAA record, extract the IPv6 address...
                            nsIPv6Addresses.add( aaaa.address );
                    } );
        }

        // decrement the count of subqueries; when we get to zero it's time to respond fire an event with our results...
        if( nsIPsubQueries.decrementAndGet() == 0 ) {

            // if we didn't get any name server IP addresses, fire a NO_NS_IP event to convey the sad, sad news...
            if( (nsIPv4Addresses.size() + nsIPv6Addresses.size()) == 0 ) {

                // take care of the logging...
                String msg = "Didn't find any IP addresses for name server: " + qr.query().questions.get( 0 ).qname.text;
                queryLog.log( msg );
                queryLog.addSubQueryLog( qr.log() );
                LOGGER.finer( msg );

                // fire a NO_NS_IP event...
                fsm.onEvent( fsm.event( Event.NO_NS_IP ) );
                return;
            }

            // otherwise, grab an IP address...
            IPAddress ip = (nsIPv4Addresses.isEmpty() ? nsIPv6Addresses.get( 0 ) : nsIPv4Addresses.get( 0 ) );

            // take care of the logging...
            String msg = "Found an IP address for name server " + qr.query().questions.get( 0 ).qname.text + ": " + ip;
            queryLog.log( msg );
            queryLog.addSubQueryLog( qr.log() );
            LOGGER.finer( msg );

            // and fire off a GOT_NS_IP event...
            fsm.onEvent( fsm.event( Event.GOT_NS_IP, ip ) );
        }
    }


    /**
     * Response handler for responses to this query (not sub-queries).  There are several possible sorts of responses:
     * <ul>
     *     <li>Response code OK, answer authoritative, with answers: the original query has been satisfied; fire a NS_ANSWER event.</li>
     *     <li>Response code NAME_ERROR, answer authoritative: the domain name being queried does not exist; fire a NS_ANSWER event.</li>
     *     <li>Response code OK, answer authoritative, no answers, at least one authority, possibly some additional records: fire a NS_ANSWER event.</li>
     *     <li>The message was received on UDP and was truncated; fire a TRUNCATED event.</li>
     *     <li>For all other cases; fire a QUERY_NS_FAIL event.</li>
     * </ul>
     *
     * @param _responseMsg The {@link DNSMessage} received from a DNS server.
     * @param _transport The transport (UDP or TCP) that the message was received on.
     */
    protected void handleResponse( final DNSMessage _responseMsg, final DNSTransport _transport ) {

        Checks.required( _responseMsg, _transport );

        // log it...
        String msg = "Received response via " + _transport + ": " + _responseMsg.toString();
        queryLog.log( msg );
        LOGGER.finer( msg );

        // no matter what happens next, we need to shut down the agent...
        agent.close();

        // stuff the response away...
        responseMessage = _responseMsg;

        // if the message came in on UDP, and it was truncated, fire off a TRUNCATED event...
        if( (_transport == UDP) && responseMessage.truncated ) {

            // log it...
            msg = "Received truncated response";
            queryLog.log( msg );
            LOGGER.finer( msg );

            // fire off a TRUNCATED event...
            fsm.onEvent( fsm.event( Event.TRUNCATED ) );
            return;
        }

        // if the response was OK, fire off a NS_ANSWER event with attached message...
        if( responseMessage.responseCode == OK ) {

            // log it...
            msg = "Received OK response";
            queryLog.log( msg );
            LOGGER.finer( msg );

            // fire off a NS_ANSWER event...
            fsm.onEvent( fsm.event( Event.NS_ANSWER, responseMessage ) );
            return;
        }

        // if the response was authoritative and NAME_ERROR, then the queried name does not exist - fire off a NAME_ERROR event...
        if( responseMessage.authoritativeAnswer && (responseMessage.responseCode == NAME_ERROR)) {

            // handle the logging...
            msg = "Received a name error: '" + responseMessage.questions.get( 0 ).qname.text + "' does not exist";
            queryLog.log( msg );
            LOGGER.finer( msg );

            // fire off a QUERY_NS_FAIL event...
            fsm.onEvent( fsm.event( Event.NAME_ERROR ) );
        }

        // in all other cases, we had a failure of some kind; fire off a QUERY_NS_FAIL event...

        // log it...
        msg = "Received unusable response";
        queryLog.log( msg );
        LOGGER.finer( msg );

        // fire off a QUERY_NS_FAIL event...
        fsm.onEvent( fsm.event( Event.QUERY_NS_FAIL ) );
    }


    /**
     * Called when there is a problem of some kind that occurs before a message is received and decoded.  That means we don't have a lot of context for the error, but we still
     * need to try another server, or (if we run out of servers to try), to do some cleanup and tell the customer what happened.
     *
     * @param _msg A message describing the problem.
     * @param _cause An optional {@link Throwable} cause.
     */
    protected void handleProblem( final String _msg, final Throwable _cause ) {

        Checks.required( _msg );

        // no matter what happens next, we need to shut down the agent...
        agent.close();


        // log it...
        String msg = "Problem querying name server: " + _msg + ((_cause != null) ? " - " + _cause.getMessage() : "");
        queryLog.log( msg );
        LOGGER.finer( msg );

        // fire off a QUERY_NS_FAIL event...
        fsm.onEvent( fsm.event( Event.QUERY_NS_FAIL ) );
    }


    private record ProblemDescription( String msg, Throwable cause ){}



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
                .setRecurse(  false           )
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
        // we also have to decide if our attempt to resolve from the cache should resolve ANY queries...
        boolean resolveAny = false;
        Object attachment = _event.getData();
        if( attachment instanceof DNSMessage msg ) {

            // if the message shows a name error, return a NAME_ERROR event...
            if( msg.responseCode == NAME_ERROR )
                return _fsm.event( Event.NAME_ERROR );

            // otherwise, update the DNS cache...
            updateCacheFromMessage( msg );

            // if the attached message is an authoritative response, then we DO want to resolve ANY queries...
            resolveAny = msg.authoritativeAnswer;
        }

        // try to resolve the query through the cache...
        DNSMessage cacheResponse = cache.resolve( queryMessage, resolveAny );

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
            return _fsm.event( Event.NO_MORE_NS );
        }

        // get our list of name servers and their IP addresses...
        nameServers = getNameServers( cacheResponse );

        // return a INITIATE_NS_QUERY event...
        return _fsm.event( Event.INITIATE_NS_QUERY );
    }


    /**
     * Event transform that checks to see we have a complete answer, or if we need to resolve a CNAME alias.
     *
     * @param _event The FSM event being transformed. In this case, it's always a GOT_ANSWER event with an attached {@link DNSMessage}.
     * @param _fsm The FSM associated with this transformation.
     * @return A FINAL_ANSWER or a SUBQUERY_CNAME event.
     */
    private FSMEvent<Event> answerCheck( final FSMEvent<Event> _event, final FSM<State, Event> _fsm  ) {

        // get the DNS message attached to our event...
        DNSMessage msg = (DNSMessage) _event.getData();

        // if we have a single answer, it's a CNAME record, and our query was neither a CNAME nor an ANY query, then we need to follow the CNAME trail...
        if( (msg.answers.size() == 1) && (msg.answers.get( 0 ) instanceof CNAME cname) && !((question.qtype == CNAME) || (question.qtype == ANY)) ) {

            // save the CNAME in our accumulated answers...
            answers.add( cname );

            // return a SUBQUERY_CNAME event with attached name to resolve...
            return _fsm.event( Event.SUBQUERY_CNAME, cname.cname.text );
        }

        // if the response message had no answers, then the CNAME doesn't resolve to the kind of record we queried for; we need to return no answers...
        if( msg.answers.size() == 0 )
            answers.clear();

            // otherwise, we must have the final answer - so save the answers and return a FINAL_ANSWER event...
        else
            answers.addAll( msg.answers );

        // ...and now we have the answer...
        return _fsm.event( Event.FINAL_ANSWER );
    }


    /**
     * Event transform that ensures that a name server is queried.  The name servers that could be queried are in the {@code nameServers} list of {@link IPHost}s, in order. Each
     * of the items in the list may or may not have an associated IP address.  Four events are processed by this transform: INITIATE_NS_QUERY, QUERY_NS_FAIL, NO_NS_IP, and
     * GOT_NS_IP.  Returned events are:
     * <ul>
     *     <li>QUERY_NS (with an attached {@link IPAddress}) to initiate a query of an authoritative DNS server.</li>
     *     <li>SUBQUERY_NS_IP (with an attached {@link String} hostname) to initiate a subquery for the IP address of the given hostname (a DNS server).</li>
     *     <li>NO_MORE_NS if there are no more name servers to query.</li>
     * </ul>
     *
     * @param _event The FSM event being transformed. In this case, it's always a GOT_ANSWER event with an attached {@link DNSMessage}.
     * @param _fsm The FSM associated with this transformation.
     * @return A QUERY_NS, SUBQUERY_NS_IP, or NO_MORE_NS event.
     */
    private FSMEvent<Event> ensureNameServer( final FSMEvent<Event> _event, final FSM<State, Event> _fsm  ) {

        // if we got an INITIATE_NS_QUERY event, initialize our transport to UDP...
        if( _event.event == Event.INITIATE_NS_QUERY )
            transport = UDP;

        // if we got a TRUNCATED event, initialize our transport to TCP...
        if( _event.event == Event.TRUNCATED )
            transport = TCP;

        // if we are getting a failure of some kind, remove the first entry in our list...
        if( (_event.event == Event.QUERY_NS_FAIL) || (_event.event == Event.NO_NS_IP) ) {

            // handle the logging...
            String msg = "Name server " + nameServers.get( 0 ).hostname + " failed: " + _event.event;
            LOGGER.finer( msg );
            queryLog.log( msg );

            // remove the first name server...
            nameServers.remove( 0 );
        }

        // otherwise, if we just got a name server IP address, add it to the first entry in our list...
        else if( _event.event == Event.GOT_NS_IP ) {

            // get the IP from the event...
            IPAddress ip = (IPAddress) _event.getData();

            // handle the logging...
            String msg = "Got IP for name server " + nameServers.get( 0 ).hostname + ": " + ip;
            LOGGER.finer( msg );
            queryLog.log( msg );

            // update our nameserver list...
            nameServers.set( 0, nameServers.get( 0 ).add( ip ) );
        }

        // if we have no more name servers, return a NO_MORE_NS event...
        if( nameServers.isEmpty() ) {

            // handle the logging...
            String msg = "No more name servers to query for " + question.toString();
            LOGGER.finer( msg );
            queryLog.log( msg );

            // return NO_MORE_NS...
            return _fsm.event( Event.NO_MORE_NS );
        }

        // get the name server we're working on...
        IPHost nameServer = nameServers.get( 0 );


        // if the first name server has no IP address, return a SUBQUERY_NS_IP (with attached hostname string) to initiate a subquery for the name server's IP address...
        if( nameServer.ipAddresses.isEmpty() ) {

            // handle the logging...
            String msg = "Initiating subquery for IP address for host: " + nameServer.hostname;
            LOGGER.finer( msg );
            queryLog.log( msg );

            // return a SUBQUERY_NS_IP event...
            return _fsm.event( Event.SUBQUERY_NS_IP, nameServer.hostname );
        }

        // If we make it to here, then the nameServer variable contains the name server we want to query, and it has an IP address.
        // It's time to try to initiate a query...

        // Create an agent for our name server...
        ServerSpec spec = new ServerSpec( RECURSIVE_NAME_SERVER_TIMEOUT_MS, 0, nameServer.hostname, new InetSocketAddress( nameServer.getInetAddress(), DNS_SERVER_PORT ) );
        agent = new DNSServerAgent( resolver, this, nio, executor, spec );

        // handle logging...
        String msg = "Sending query for " + question + " to " + nameServer.hostname + " at " + nameServer.getIPAddresses().get( 0 ) + ", via " + transport;
        LOGGER.finest( msg );
        queryLog.log( msg );

        // send the query...
        Outcome<?> sendOutcome = agent.sendQuery( queryMessage, transport );

        // if the query couldn't be sent, return a QUERY_NS_FAIL event, and we'll try the next name server, if we have one...
        if( sendOutcome.notOk() ) {

            // handle the logging...
            msg = "Failure when sending query to " + nameServer.hostname + " at " + nameServer.getIPAddresses().get( 0 ) + ", via " + transport + "; " + sendOutcome.msg();
            LOGGER.finer( msg );
            queryLog.log( msg );

            // return the QUERY_NS_FAIL event...
            return _fsm.event( Event.QUERY_NS_FAIL );
        }

        // return a SUBQUERY_NS_IP event...
        return _fsm.event( Event.QUERY_NS );
    }


    /**
     * Transition action on IDLE::SUBQUERY_CNAME or QUERY_NS::SUBQUERY_CNAME, to initiate the sub-query.  The SUBQUERY_CNAME event has a string attached with the
     * canonical name to query.
     *
     * @param _transition The transition that triggered this action, in this case either IDLE::SUBQUERY_CNAME or QUERY_NS::SUBQUERY_CNAME.
     * @param _event The event that triggered this action, in this case always SUBQUERY_CNAME.
     */
    private void initiateCNAMESubquery( final FSMTransition<State, Event> _transition, FSMEvent<Event> _event  ) {

        // send off a sub-query to get the next element of the CNAME chain, or our actual answer...
        String canonicalName = (String) _event.getData();
        DNSDomainName nextDomain = DNSDomainName.fromString( canonicalName ).info();
        DNSRRType nextType = question.qtype;

        String msg = "Got CNAME; firing " + nextDomain.text + " " + nextType + " record sub-query from query " + id;
        LOGGER.finest( msg );
        queryLog.log( msg );
        DNSQuestion cnameSubqueryQuestion = new DNSQuestion( nextDomain, nextType );
        DNSRecursiveQuery recursiveQuery = new DNSRecursiveQuery( resolver, cache, nio, executor, activeQueries, cnameSubqueryQuestion, resolver.getNextID(),
                this::handleCNAMESubqueryResponse );
        recursiveQuery.initiate();
    }


    /**
     * Transition action on IDLE::SUBQUERY_NS_IP, SUB_QUERY_NS_IP::SUBQUERY_NS_IP, or QUERY_NS::SUBQUERY_NS_IP, to initiate the sub-query.  The SUBQUERY_NS_IP event has a string
     * attached with the hostname to query.
     *
     * @param _transition The transition that triggered this action, in this case either IDLE::SUBQUERY_NS_IP or QUERY_NS::SUBQUERY_NS_IP.
     * @param _event The event that triggered this action, in this case, always SUBQUERY_NS_IP.
     */
    private void initiateNSIPSubquery( final FSMTransition<State, Event> _transition, FSMEvent<Event> _event  ) {

        // set up the count of subqueries...
        nsIPsubQueries.set( (resolver.useIPv4() && resolver.useIPv6()) ? 2 : 1 );

        // set up to send off our queries...
        nsIPv4Addresses.clear();
        nsIPv6Addresses.clear();
        String dnsHost = (String) _event.getData();
        DNSDomainName dnsDomainName = DNSDomainName.fromString( dnsHost ).info();

        // if we're using IPv4, query for "A" records...
        if( resolver.useIPv4() ) {

            // handle the logging...
            String msg = "Firing " + dnsDomainName.text + " A record sub-query from query " + id;
            LOGGER.finest( msg );
            queryLog.log( msg );

            // and then the actual subquery...
            DNSQuestion question = new DNSQuestion( dnsDomainName, DNSRRType.A );
            DNSRecursiveQuery recursiveQuery = new DNSRecursiveQuery( resolver, cache, nio, executor, activeQueries, question, resolver.getNextID(),
                    this::handleNSIPSubqueryResponse );
            recursiveQuery.initiate();
        }

        // if we're using IPv6, query for "AAAA" records...
        if( resolver.useIPv6() ) {

            // handle the logging...
            String msg = "Firing " + dnsDomainName.text + " AAAA record sub-query from query " + id;
            LOGGER.finest( msg );
            queryLog.log( msg );

            // and then the actual subquery...
            DNSQuestion question = new DNSQuestion( dnsDomainName, DNSRRType.AAAA );
            DNSRecursiveQuery recursiveQuery = new DNSRecursiveQuery( resolver, cache, nio, executor, activeQueries, question, resolver.getNextID(),
                    this::handleNSIPSubqueryResponse );
            recursiveQuery.initiate();
        }
    }


    /**
     * Transition action on all the transitions to ERROR_TERMINATION state.  This action analyzes the event and constructs an appropriated notification to the
     * caller, and sends it.
     *
     * @param _transition The transition that triggered this action.
     * @param _event The event that triggered this action.
     */
    private void notifyError( final FSMTransition<State, Event> _transition, FSMEvent<Event> _event  ) {

        // analyze the error and prepare the notification...
        String msg;
        DNSResolverError error;
        switch( _event.event ) {

            case NO_MORE_NS -> {
                msg = "No more name servers to query";
                error = NO_NAME_SERVERS;
            }

            case MALFORMED_QUERY -> {
                msg = "Malformed query: " + queryMessage;
                error = BAD_QUERY;
            }

            case NO_ROOT_HINTS -> {
                msg = "No root hints available";
                error = ROOT_HINTS_PROBLEMS;
            }

            case CNAME_ERROR -> {
                ProblemDescription pd = (ProblemDescription) _event.getData();
                msg = pd.msg;
                error = NETWORK;
            }

            default -> throw new IllegalStateException( "Received an unrecognized event type: " + _event.event );
        }

        // handle logging...
        queryLog.log( msg );
        LOGGER.finest( msg );

        // notify our customer about the awfulness that just happened...
        handler.accept( queryOutcome.notOk(
                msg,
                new DNSResolverException( msg, error ),
                new QueryResult( queryMessage, null, queryLog )
        ) );
    }


    /**
     * Transition action on IDLE::FINAL_ANSWER, QUERY_NS::FINAL_ANSWER, or SUB_QUERY_CNAME::FINAL_ANSWER that notifies the client that an answer was obtained from a DNS server.
     *
     * @param _transition The transition that triggered this action.
     * @param _event The event that triggered this action.
     */
    private void notifyAnswer( final FSMTransition<State, Event> _transition, FSMEvent<Event> _event ) {

        // build our response message...
        DNSMessage.Builder builder = new DNSMessage.Builder();
        builder.addQuestion( question );
        answers.forEach( builder::addAnswer );
        builder.setResponse( true );
        builder.setAuthoritativeAnswer( true );
        responseMessage = builder.getMessage();

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
                "Domain does not exist: '" + question.qname.text + "'",
                new DNSServerException( "Domain does not exist: '" + question.qname.text + "'", NAME_ERROR ),
                new QueryResult( queryMessage, null, queryLog )
        ) );
    }


    /**
     * Simple event listener to log events seen by the FSM.
     *
     * @param _event The event.
     */
    private void eventListener( final FSMEvent<Event> _event ) {

        // get the message, keeping it to a single line...
        String msg = "Event: " + _event.event + ((_event.getData() == null )
                ? ""
                : ", data: " + _event.getData().toString().split( "\\n" )[0] );

        // log it...
        queryLog.log( msg );
        LOGGER.finest( msg );
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
        SUB_QUERY_CNAME,              // Send sub-query for CNAME resolution and wait for a response...
        QUERY_NS,                     // Send query to DNS server and wait for a response...
        ERROR_TERMINATION,            // Terminate the query because of an error...
        ANSWER_TERMINATION            // Terminate the query because an answer for the queried name was found...
    }


    private enum Event {
        INITIATE,          // Initiate the recursive DNS query...
        NO_ROOT_HINTS,     // Tried to resolve from cache, but couldn't even get root hints...
        MALFORMED_QUERY,   // Tried to resolve from cache, but the cache didn't understand the query...
        GOT_ANSWER,        // Tried to resolve from cache, and got some answers, but what sort of answer isn't known yet...
        NO_MORE_NS,        // Tried to resolve from cache, got no answers and also no name servers to query...
        INITIATE_NS_QUERY, // Kick off the process of querying a name server...
        QUERY_NS_FAIL,     // Query of name server failed...
        QUERY_NS,          // Query name server...
        SUBQUERY_NS_IP,    // Sub-query for a name server's IP address...
        GOT_NS_IP,         // Got an IP address for a name server...
        NO_NS_IP,          // Failed to get an IP address for a name server...
        NS_ANSWER,         // Got an answer from a name server query...
        NAME_ERROR,        // Received an authoritative name error (queried name does not exist)...
        SUBQUERY_CNAME,    // Sub-query the canonical name...
        FINAL_ANSWER,      // Got the final answer...
        CNAME_ERROR,       // Got an error when querying for CNAME resolution...
        TRUNCATED,         // Got a truncated response...
    }


    /**
     * Create and return the engine controller FSM.
     *
     * @return the FSM created
     */
    private FSM<State, Event> createFSM() {

        // create our FSM specification with the initial state and an example event...
        FSMSpec<State, Event> spec = new FSMSpec<>( State.IDLE, Event.INITIATE );

        // mark our terminal states...
        spec.setStateTerminal( State.ERROR_TERMINATION          );
        spec.setStateTerminal( State.ANSWER_TERMINATION         );

        // set up our on-entry state actions...
        spec.setStateOnEntryAction( State.IDLE,                       this::init        );
        spec.setStateOnEntryAction( State.ERROR_TERMINATION,          this::shutdown    );
        spec.setStateOnEntryAction( State.ANSWER_TERMINATION,         this::shutdown    );

        // add all the FSM state transitions for our FSM...
        spec.addTransition( State.IDLE,            Event.SUBQUERY_CNAME,      this::initiateCNAMESubquery,      State.SUB_QUERY_CNAME      );
        spec.addTransition( State.QUERY_NS,        Event.SUBQUERY_CNAME,      this::initiateCNAMESubquery,      State.SUB_QUERY_CNAME      );
        spec.addTransition( State.SUB_QUERY_CNAME, Event.SUBQUERY_CNAME,      this::initiateCNAMESubquery,      State.SUB_QUERY_CNAME      );
        spec.addTransition( State.IDLE,            Event.SUBQUERY_NS_IP,      this::initiateNSIPSubquery,       State.SUB_QUERY_NS_IP      );
        spec.addTransition( State.QUERY_NS,        Event.SUBQUERY_NS_IP,      this::initiateNSIPSubquery,       State.SUB_QUERY_NS_IP      );
        spec.addTransition( State.SUB_QUERY_NS_IP, Event.SUBQUERY_NS_IP,      this::initiateNSIPSubquery,       State.SUB_QUERY_NS_IP      );
        spec.addTransition( State.IDLE,            Event.FINAL_ANSWER,        this::notifyAnswer,               State.ANSWER_TERMINATION   );
        spec.addTransition( State.QUERY_NS,        Event.FINAL_ANSWER,        this::notifyAnswer,               State.ANSWER_TERMINATION   );
        spec.addTransition( State.SUB_QUERY_CNAME, Event.FINAL_ANSWER,        this::notifyAnswer,               State.ANSWER_TERMINATION   );
        spec.addTransition( State.QUERY_NS,        Event.NAME_ERROR,          this::notifyNameError,            State.ERROR_TERMINATION    );
        spec.addTransition( State.IDLE,            Event.QUERY_NS,            null,                             State.QUERY_NS             );
        spec.addTransition( State.QUERY_NS,        Event.QUERY_NS,            null,                             State.QUERY_NS             );
        spec.addTransition( State.SUB_QUERY_NS_IP, Event.QUERY_NS,            null,                             State.QUERY_NS             );
        spec.addTransition( State.IDLE,            Event.NO_ROOT_HINTS,       this::notifyError,                State.ERROR_TERMINATION    );
        spec.addTransition( State.IDLE,            Event.NO_MORE_NS,          this::notifyError,                State.ERROR_TERMINATION    );
        spec.addTransition( State.QUERY_NS,        Event.NO_MORE_NS,          this::notifyError,                State.ERROR_TERMINATION    );
        spec.addTransition( State.SUB_QUERY_NS_IP, Event.NO_MORE_NS,          this::notifyError,                State.ERROR_TERMINATION    );
        spec.addTransition( State.IDLE,            Event.MALFORMED_QUERY,     this::notifyError,                State.ERROR_TERMINATION    );
        spec.addTransition( State.SUB_QUERY_CNAME, Event.CNAME_ERROR,         this::notifyError,                State.ERROR_TERMINATION    );

        // add our event transforms...
        spec.addEventTransform( Event.INITIATE,          this::cacheCheck       );
        spec.addEventTransform( Event.NS_ANSWER,         this::cacheCheck       );
        spec.addEventTransform( Event.GOT_ANSWER,        this::answerCheck      );
        spec.addEventTransform( Event.INITIATE_NS_QUERY, this::ensureNameServer );
        spec.addEventTransform( Event.QUERY_NS_FAIL,     this::ensureNameServer );
        spec.addEventTransform( Event.TRUNCATED,         this::ensureNameServer );
        spec.addEventTransform( Event.NO_NS_IP,          this::ensureNameServer );
        spec.addEventTransform( Event.GOT_NS_IP,         this::ensureNameServer );

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
