package com.dilatush.dns.misc;

/**
 * Enumerates all the sources of errors originating in the {@code com.dilatush.dns} package (as opposed to those originating in the DNS server).
 */
public enum DNSResolverError {

    /** Encountered a problem when trying to use the network. */
    NETWORK,

    /** DNS query timed out. */
    TIMEOUT,

    /** Root hints could not be read. */
    ROOT_HINTS_PROBLEMS,

    /** Encoder buffer overflow. */
    ENCODER_BUFFER_OVERFLOW,

    /** Decoder buffer underflow. */
    DECODER_BUFFER_UNDERFLOW,

    /** Message received on the wrong transport (TCP or UDP). */
    RECEIVED_MESSAGE_ON_WRONG_TRANSPORT,

    /** Invalid domain name */
    INVALID_DOMAIN_NAME,

    /** Pseudo-type UNIMPLEMENTED cannot be encoded. */
    UNIMPLEMENTED_UNENCODABLE,

    /** Invalid resource record data (either length or contents). */
    INVALID_RESOURCE_RECORD_DATA,

    /** Invalid resource record class code, not decodable. */
    INVALID_RESOURCE_RECORD_CLASS_CODE,

    /** Could not find IPs of any root servers. */
    NO_ROOT_SERVERS,

    /** Query message is not a query or has no question. */
    BAD_QUERY,

    /** Could not find name servers to satisfy the query. */
    NO_NAME_SERVERS
}
