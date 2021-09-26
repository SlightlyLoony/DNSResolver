package com.dilatush.dns.agent;

import java.util.logging.Level;
import java.util.logging.Logger;

import static com.dilatush.util.General.getLogger;

/**
 * @author Tom Dilatush  tom@dilatush.com
 */
public class DNSQueryTimeout extends AbstractTimeout {

    final static private Logger LOGGER = getLogger();

    private final Runnable handler;

    public DNSQueryTimeout( final long _timeoutMillis, final Runnable _handler ) {
        super( _timeoutMillis );
        handler = _handler;
    }


    @Override
    protected void onTimeout() {
        LOGGER.log( Level.FINEST, "Query timeout" );
        handler.run();
    }
}
