package com.dilatush.dns;

import com.dilatush.util.Outcome;
import com.dilatush.dns.message.DNSDomainName;
import com.dilatush.dns.message.DNSQuestion;
import com.dilatush.dns.message.DNSRRClass;
import com.dilatush.dns.message.DNSRRType;
import com.dilatush.dns.rr.A;
import com.dilatush.dns.rr.DNSResourceRecord;

import java.net.Inet4Address;
import java.util.ArrayList;
import java.util.List;

/**
 * Static container class for functions related to DNS.
 *
 * @author Tom Dilatush  tom@dilatush.com
 */
public class DNSUtil {

    private static final Outcome.Forge<DNSQuestion> outcomeQuestion = new Outcome.Forge<>();


    /**
     * Returns a list of all the IPv4 addresses found in any A records contained in the given list of DNS resource records.
     *
     * @param _rrs the list of DNS resource records to search.
     * @return a list of IPv4 addresses found in any A records contained in the given list of DNS resource records.
     */
    public static List<Inet4Address> extractIPv4Addresses( final List<DNSResourceRecord> _rrs ) {
        List<Inet4Address> result = new ArrayList<>();
        _rrs.stream().filter( (rr) -> rr instanceof A ).forEach( (rr) -> result.add( ((A)rr).address ) );
        return result;
    }


    public static Outcome<DNSQuestion> getQuestion( final String _domainName, final DNSRRType _type, final DNSRRClass _class ) {

        Outcome<DNSDomainName> dno = DNSDomainName.fromString( _domainName );
        return dno.notOk()
                ? outcomeQuestion.notOk( dno.msg(), dno.cause() )
                : outcomeQuestion.ok( new DNSQuestion( dno.info(), _type, _class ) );
    }


    public static Outcome<DNSQuestion> getQuestion( final String _domainName, final DNSRRType _type ) {
        return getQuestion( _domainName, _type, DNSRRClass.IN );
    }


    /**
     * Returns a string representation of the given list of {@link DNSResourceRecord}s, with each resource record on its own line.
     *
     * @param _rrs The list resource records to get a string for.
     * @return the string representation of the list of resource records.
     */
    public static String toString( final List<DNSResourceRecord> _rrs ) {
        StringBuilder sb = new StringBuilder();
        _rrs.forEach( (rr) -> {sb.append( rr ); sb.append( "\n" );} );
        return sb.toString();
    }


    // prevent instantiation...
    private DNSUtil() {}
}
