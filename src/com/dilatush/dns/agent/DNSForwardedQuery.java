package com.dilatush.dns.agent;

import com.dilatush.util.Checks;
import com.dilatush.util.ExecutorService;
import com.dilatush.util.General;
import com.dilatush.util.Outcome;
import com.dilatush.dns.DNSResolver;
import com.dilatush.dns.DNSResolver.AgentParams;
import com.dilatush.dns.cache.DNSCache;
import com.dilatush.dns.message.DNSMessage;
import com.dilatush.dns.message.DNSOpCode;
import com.dilatush.dns.message.DNSQuestion;

import java.util.List;
import java.util.Map;
import java.util.function.Consumer;
import java.util.logging.Logger;

/**
 * Instances of this class contain the elements and state of a DNS query, and provide methods that implement the resolution of that query.
 */
public class DNSForwardedQuery extends DNSQuery {

    private static final Logger LOGGER                           = General.getLogger();


    public DNSForwardedQuery( final DNSResolver _resolver, final DNSCache _cache, final DNSNIO _nio, final ExecutorService _executor,
                              final Map<Short,DNSQuery> _activeQueries, final DNSQuestion _question, final int _id,
                              final List<AgentParams> _agents, final Consumer<Outcome<QueryResult>> _handler ) {
        super( _resolver, _cache, _nio, _executor, _activeQueries, _question, _id, _agents, _handler );

        Checks.required( _agents );

        queryLog.log("New recursive query " + question );
    }


    public Outcome<?> initiate( final DNSTransport _initialTransport ) {

        Checks.required( _initialTransport, "initialTransport");

        queryLog.log("Initial query" );
        LOGGER.finer( "Initiating new recursive query - ID: " + id + ", " + question.toString() );

        initialTransport = _initialTransport;

        // if we have no agents, then revert to an iterative query...
        if( agents.isEmpty() ) {
            DNSQuery itQuery = new DNSRecursiveQuery( resolver, cache, nio, executor, activeQueries, question, id, handler );
            return itQuery.initiate( _initialTransport );
        }

        return query();
    }


    protected Outcome<?> query() {

        transport = initialTransport;

        // figure out what agent we're going to use...
        agent = new DNSServerAgent( resolver, this, nio, executor, agents.remove( 0 ) );
        LOGGER.finer( "Recursive query - ID: " + id + ", " + question.toString() + ", using " + agent.name );

        DNSMessage.Builder builder = new DNSMessage.Builder();
        builder.setOpCode( DNSOpCode.QUERY );
        builder.setRecurse( true );
        builder.setId( id & 0xFFFF );
        builder.addQuestion( question );

        queryMessage = builder.getMessage();

        queryLog.log("Sending recursive query to " + agent.name + " via " + transport );

        Outcome<?> sendOutcome = agent.sendQuery( queryMessage, transport );

        return sendOutcome.ok()
                ? queryOutcome.ok()
                : queryOutcome.notOk( sendOutcome.msg(), sendOutcome.cause() );
    }


    protected void handleOK() {

        basicOK();

        // send the results, and then we're done...
        handler.accept( queryOutcome.ok( new QueryResult( queryMessage, responseMessage, queryLog )) );
    }


    public String toString() {
        return "DNSQuery: " + responseMessage.answers.size() + " answers";
    }
}
