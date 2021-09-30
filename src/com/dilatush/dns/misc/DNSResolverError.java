package com.dilatush.dns.misc;

public enum DNSResolverError {

    /** Encountered a problem when trying to use the network. */
    NETWORK,

    /** The TCP queue of messages to be sent is full. */
    TCP_SEND_QUEUE_FULL,

    /** The UDP queue of messages to be sent is full. */
    UDP_SEND_QUEUE_FULL,

    /** Root hints could not be read. */
    ROOT_HINTS_PROBLEMS,

    /** Encoder buffer overflow. */
    ENCODER_BUFFER_OVERFLOW,

    /** Decoder buffer underflow. */
    DECODER_BUFFER_UNDERFLOW,

    /** Invalid domain name */
    INVALID_DOMAIN_NAME,

    /** Pseudo-type UNIMPLEMENTED cannot be encoded. */
    UNIMPLEMENTED_UNENCODABLE,

    /** Invalid resource record data (either length or contents). */
    INVALID_RESOURCE_RECORD_DATA,

    /** Invalid resource record class code, not decodable. */
    INVALID_RESOURCE_RECORD_CLASS_CODE,

    /** Could not find IPs of any root servers */
    NO_ROOT_SERVERS;
}
