package com.dilatush.dns.misc;

/**
 * Enumerates the possible ways that the DNS resolver can use name server IP addresses.
 *
 * @author Tom Dilatush  tom@dilatush.com
 */
public enum DNSIPVersion {

    /** The DNS resolver will only use the IPv4 addresses of name servers. */
    IPv4,

    /** The DNS resolver will only use the IPv6 addresses of name servers. */
    IPv6,

    /** The DNS resolver will use either IPv4 or IPv6 addresses of name servers. */
    IPvBoth
}
