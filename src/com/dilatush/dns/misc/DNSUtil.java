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
     * will have a hostname with the given queried FQDN, effectively hiding any CNAME chain that was followed to the A record.
     *
     * @param _rrs The list of DNS resource records to search.
     * @param _queriedFQDN The originally queried FQDN (before any CNAME chains were followed).
     * @return A list of IPv4 addresses found in any A records contained in the given list of DNS resource records.
     */
    public static List<Inet4Address> extractIPv4Addresses( final List<DNSResourceRecord> _rrs, final String _queriedFQDN ) {

        Checks.required( _rrs, _queriedFQDN );

        List<Inet4Address> result = new ArrayList<>();           // a place for our results...
        _rrs.stream()                                            // get a stream of resource records from the given list...
                .filter( (rr) -> rr instanceof A )               // look at just the A records...
                .forEach( (rr) -> {                              // for each A record we found...
                    Inet4Address ip = ((A)rr).address;           // get the IP address, which may not have the right hostname...
                    ip = setHostName( ip, _queriedFQDN );        // set the right hostname...
                    result.add( ip );                            // add the massaged IP to our list of results...
                } );
        return result;
    }


    /**
     * Set the hostname of the given {@link Inet4Address} to the given hostname (without changing the IP address), and return the result.
     *
     * @param _ip The {@link Inet4Address} to set the hostname in.
     * @param _hostname The hostname to set.
     * @return The {@link Inet4Address} with the given hostname.
     */
    public static Inet4Address setHostName( final Inet4Address _ip, final String _hostname ) {

        try {
            return (Inet4Address) Inet4Address.getByAddress( _hostname, _ip.getAddress() );
        }

        // this should be impossible, as we got the address bytes from an Inet4Address instance...
        catch( UnknownHostException _e ) {
            throw new IllegalStateException( "IP address was wrong length" );
        }
    }


    /**
     * Returns a list of all the IPv6 addresses found in any AAAA records contained in the given list of DNS resource records.  The resulting {@link Inet6Address} instances
     * will have a hostname with the given queried FQDN, effectively hiding any CNAME chain that was followed to the AAAA record.
     *
     * @param _rrs The list of DNS resource records to search.
     * @param _queriedFQDN The originally queried FQDN (before any CNAME chains were followed).
     * @return A list of IPv6 addresses found in any A records contained in the given list of DNS resource records.
     */
    public static List<Inet6Address> extractIPv6Addresses( final List<DNSResourceRecord> _rrs, final String _queriedFQDN ) {

        Checks.required( _rrs, _queriedFQDN );

        List<Inet6Address> result = new ArrayList<>();           // a place for our results...
        _rrs.stream()                                            // get a stream of resource records from the given list...
                .filter( (rr) -> rr instanceof AAAA )            // look at just the AAAA records...
                .forEach( (rr) -> {                              // for each AAAA record we found...
                    Inet6Address ip = ((AAAA)rr).address;        // get the IP address, which may not have the right hostname...
                    ip = setHostName( ip, _queriedFQDN );        // set the right hostname...
                    result.add( ip );                            // add the massaged IP to our list of results...
                } );
        return result;
    }


    /**
     * Set the hostname of the given {@link Inet6Address} to the given hostname (without changing the IP address), and return the result.
     *
     * @param _ip The {@link Inet6Address} to set the hostname in.
     * @param _hostname The hostname to set.
     * @return The {@link Inet6Address} with the given hostname.
     */
    public static Inet6Address setHostName( final Inet6Address _ip, final String _hostname ) {

        try {
            return (Inet6Address) Inet6Address.getByAddress( _hostname, _ip.getAddress() );
        }

        // this should be impossible, as we got the address bytes from an Inet4Address instance...
        catch( UnknownHostException _e ) {
            throw new IllegalStateException( "IP address was wrong length" );
        }
    }


    /**
     * Returns a list of all the text found in any TXT records contained in the given list of DNS resource records.  The data in the TXT records are decoded as ASCII.
     *
     * @param _rrs The list of DNS resource records to search.
     * @return A list of strings found in any TXT records contained in the given list of DNS resource records.
     */
    public static List<String> extractText( final List<DNSResourceRecord> _rrs ) {

        Checks.required( _rrs );

        List<String> result = new ArrayList<>();                         // a place for our results...
        _rrs.stream()                                                    // get a stream of resource records from the given list...
                .filter( (rr) -> rr instanceof TXT )                     // look at just the TXT records...
                .forEach( ( rr) -> result.addAll( ((TXT)rr).ascii ) );   // for each TXT record, add all the lines we had...
        return result;
    }


    /**
     * Returns a list of all the domain names of name server found in NS records contained in the given list of DNS resource records.
     *
     * @param _rrs The list of DNS resource records to search.
     * @return A list of all the domain names of name server found in NS records contained in the given list of DNS resource records.
     */
    public static List<String> extractNameServers( final List<DNSResourceRecord> _rrs ) {

        Checks.required( _rrs );

        List<String> result = new ArrayList<>();                               // a place for our results...
        _rrs.stream()                                                          // get a stream of resource records from the given list...
                .filter( (rr) -> rr instanceof NS )                            // look at just the NS records...
                .forEach( ( rr) -> result.add( ((NS)rr).nameServer.text ) );   // add the domain name of the name server to our results...
        return result;
    }


    /**
     * Attempt to create a new instance of {@link DNSQuestion} from the given domain name, {@link DNSRRType}, and {@link DNSRRClass}.  If successful, returns ok with the new
     * {@link DNSQuestion} as the information.  Otherwise, returns "not ok" with an explanation.
     *
     * @param _domainName The domain name for the new question
     * @param _type The type of resource record the new question concerns.
     * @param _class The class of resource record the new question concerns.
     * @return An {@link Outcome Outcome&lt;DNSQuestion&gt;} with the result.
     */
    public static Outcome<DNSQuestion> getQuestion( final String _domainName, final DNSRRType _type, final DNSRRClass _class ) {

        Checks.required( _domainName, _type, _class );

        // get a DNSDomainName instance from the given domain name...
        Outcome<DNSDomainName> dno = DNSDomainName.fromString( _domainName );
        return dno.notOk()
                ? outcomeQuestion.notOk( "Could not create a DNSQuestion instance; " + dno.msg(), dno.cause() )
                : outcomeQuestion.ok( new DNSQuestion( dno.info(), _type, _class ) );
    }


    /**
     * Attempt to create a new instance of {@link DNSQuestion} from the given domain name, {@link DNSRRType}, for the class {@link DNSRRClass#IN} (Internet).  If successful,
     * returns ok with the new  {@link DNSQuestion} as the information.  Otherwise, returns "not ok" with an explanation.
     *
     * @param _domainName The domain name for the new question
     * @param _type The type of resource record the new question concerns.
     * @return An {@link Outcome Outcome&lt;DNSQuestion&gt;} with the result.
     */
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

        Checks.required( _rrs );

        StringBuilder sb = new StringBuilder();
        _rrs.forEach( (rr) -> {
            sb.append( rr );
            sb.append( "\n" );
        } );
        return sb.toString();
    }


    /** prevent instantiation. */
    private DNSUtil() {}
}
