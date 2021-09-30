package com.dilatush.dns.misc;

import com.dilatush.dns.message.DNSDomainName;
import com.dilatush.dns.message.DNSQuestion;
import com.dilatush.dns.message.DNSRRClass;
import com.dilatush.dns.message.DNSRRType;
import com.dilatush.dns.rr.*;
import com.dilatush.util.Checks;
import com.dilatush.util.Outcome;

import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.UnknownHostException;
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
     * Returns a list of all the IPv4 addresses found in any A records contained in the given list of DNS resource records.  The resulting {@link Inet4Address} instances
     * will have a hostname with the given queried FQDN, effectively hiding any CNAME chain that was followed.
     *
     * @param _rrs The list of DNS resource records to search.
     * @param _queriedFQDN The originally queried FQDN (before any CNAME chains were followed).
     * @return A list of IPv4 addresses found in any A records contained in the given list of DNS resource records.
     */
    public static List<Inet4Address> extractIPv4Addresses( final List<DNSResourceRecord> _rrs, final String _queriedFQDN ) {

        Checks.required( _rrs, _queriedFQDN );

        List<Inet4Address> result = new ArrayList<>();
        _rrs.stream()
                .filter( (rr) -> rr instanceof A )
                .forEach( (rr) -> {
                    Inet4Address ip = ((A)rr).address;
                    try {
                        result.add( (Inet4Address) Inet4Address.getByAddress( _queriedFQDN, ip.getAddress() ) );
                    }
                    catch( UnknownHostException _e ) {
                        // this should be impossible...
                        throw new IllegalStateException( "IP address was wrong length" );
                    }
                } );
        return result;
    }


    /**
     * Returns a list of all the IPv6 addresses found in any AAAA records contained in the given list of DNS resource records.  The resulting {@link Inet6Address} instances
     * will have a hostname with the given queried FQDN, effectively hiding any CNAME chain that was followed.
     *
     * @param _rrs The list of DNS resource records to search.
     * @param _queriedFQDN The originally queried FQDN (before any CNAME chains were followed).
     * @return A list of IPv6 addresses found in any A records contained in the given list of DNS resource records.
     */
    public static List<Inet6Address> extractIPv6Addresses( final List<DNSResourceRecord> _rrs, final String _queriedFQDN ) {

        Checks.required( _rrs, _queriedFQDN );

        List<Inet6Address> result = new ArrayList<>();
        _rrs.stream()
                .filter( (rr) -> rr instanceof AAAA )
                .forEach( (rr) -> {
                    Inet6Address ip = ((AAAA)rr).address;
                    try {
                        result.add( (Inet6Address) Inet6Address.getByAddress( _queriedFQDN, ip.getAddress() ) );
                    }
                    catch( UnknownHostException _e ) {
                        // this should be impossible...
                        throw new IllegalStateException( "IP address was wrong length" );
                    }
                } );
        return result;
    }


    /**
     * Returns a list of all the text found in any TXT records contained in the given list of DNS resource records.  The data in the TXT records are decoded as ASCII.
     *
     * @param _rrs The list of DNS resource records to search.
     * @return A list of strings found in any TXT records contained in the given list of DNS resource records.
     */
    public static List<String> extractText( final List<DNSResourceRecord> _rrs ) {
        List<String> result = new ArrayList<>();
        _rrs.stream()
                .filter( (rr) -> rr instanceof TXT )
                .forEach( ( rr) -> result.addAll( ((TXT)rr).ascii ) );
        return result;
    }


    /**
     * Returns a list of all the domain names of name server found in NS records contained in the given list of DNS resource records.
     *
     * @param _rrs The list of DNS resource records to search.
     * @return A list of all the domain names of name server found in NS records contained in the given list of DNS resource records.
     */
    public static List<String> extractNameServers( final List<DNSResourceRecord> _rrs ) {
        List<String> result = new ArrayList<>();
        _rrs.stream()
                .filter( (rr) -> rr instanceof NS )
                .forEach( ( rr) -> result.add( ((NS)rr).nameServer.text ) );
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
