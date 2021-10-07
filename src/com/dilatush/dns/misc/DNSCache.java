package com.dilatush.dns.misc;

import com.dilatush.dns.message.*;
import com.dilatush.dns.rr.DNSResourceRecord;
import com.dilatush.dns.rr.NS;
import com.dilatush.dns.rr.UNIMPLEMENTED;
import com.dilatush.util.Checks;
import com.dilatush.util.General;
import com.dilatush.util.Outcome;

import java.util.*;
import java.util.concurrent.atomic.AtomicLong;
import java.util.logging.Logger;
import java.util.stream.Collectors;

import static com.dilatush.dns.message.DNSRRType.*;
import static com.dilatush.dns.message.DNSResponseCode.*;
import static com.dilatush.dns.misc.DNSUtil.filterResourceRecords;
import static java.util.logging.Level.FINE;
import static java.util.logging.Level.SEVERE;

// TODO: add reference to root hints
// TODO: add method to resolve CNAME chains
// TODO: add method that takes a query message and produces a response message

/**
 * <p>Instances of this class implement a cache for DNS resource records for fully-qualified domain names (FQDNs).  The cache has a fixed limit on the number of resource records
 * that can be cached, set at instantiation time.  Resource records that have expired (as defined by the TTL field) are automatically purged from the cache and are never returned
 * when fetching from the cache.</p>
 * <p>The cache is intentionally very simple, allowing only for new resource records to be added, and resource records for a given FQDN to be fetched.  The design emphasizes
 * minimizing memory consumption (to allow larger caches) over performance (since even a relatively slow cache is still vastly faster than a DNS query).  Instances of this class
 * are mutable (obviously), but are threadsafe because the methods sensitive to mutation are all synchronized.</p>
 * <p>Expired resource records are purged when they are discovered (during resource record addition or fetching).  There is no explicit purge method, and the purges are never for
 * more than a few records at a time.  This means that at any given time the cache may contain any number of expired records, especially if additions and fetches are relatively
 * infrequent events.  However, in no case will an expired resource record in the cache prevent a new resource record from being added.  This "lazy" approach to purging expired
 * records has the benefit of spreading the purging work out, so there will never be a lengthy blockage due to expired record purging.</p>
 */
public class DNSCache {

    private static final Logger LOGGER = General.getLogger();

    private static final int  MIN_CACHE_SIZE                   = 1000;
    private static final int  DEFAULT_MAX_CACHE_SIZE           = 5000;
    private static final long DEFAULT_MAX_ALLOWABLE_TTL_MILLIS = 2 * 60 * 60 * 1000;  // 2 hours...

    private        final int          maxCacheSize;           // the maximum number of resource records that this cache may contain...
    private        final long         maxAllowableTTLMillis;  // the maximum (longest) time-to-live (TTL) that any resource record in the cache is allowed to have...
    private        final AtomicLong   uniqueInteger;          // differentiates ttlMap entries (see below) that have the same expiration time...
    private        final DNSRootHints rootHints;              // the root hints manager we'll use for recursive resolution...

    /****************************************************************************************************************************************************
     * The two maps below are the key data structures for the cache.
     *
     * entryMap  Maps a FQDN (as a string) to an array of DNSCacheEntry instances that contain the resource record itself (a DNSResourceRecord instance),
     *           the expiration time (in milliseconds, as returned by System.currentTimeMillis()), and the key to the entry for this resource record in
     *           ttlMap.  The array never has any empty (null) elements; each element has a (possibly expired) record.  We chose an array (as opposed to
     *           a list) because the array is always exactly the right size (minimizing memory consumption) while the array backing an array list may be
     *           substantially larger than the number of actual elements, and other forms of lists have larger elements and lower performance.
     *
     * ttlMap    Maps a DNSTTLCacheKey instance to a DNSCacheEntry.  There is one entry in this map for every resource record held in the entryMap.  The
     *           key is effectively a 128-bit integer, with the high order 64 bits being the resource record expiration time, and the low order 64 bits
     *           (the "discriminator") being a unique integer.  The map is a TreeMap, so the keys can be easily traversed in order.  The discriminator is
     *           necessary because any number of resource records may have the same expiration time; the discriminator ensures that these will all have
     *           a unique key that is still ordered from earliest-to-latest expiration time.  The DNSCacheEntry value contains all the information
     *           needed to locate a resource record in the entryMap when it's time to purge it.
     ****************************************************************************************************************************************************/
    private        final Map<String,DNSCacheEntry[]>           entryMap;  // entries are (domain name) -> (list of cache entries) for that domain...
    private        final TreeMap<DNSTTLCacheKey,DNSCacheEntry> ttlMap;    // entries are (expiration, unique long) -> (cache entry)...


    /**
     * <p>Creates a new instance of this class using the given arguments:</p>
     * <ul>
     *     <li>_maxCacheSize - the maximum number of DNS resource records that may be stored in this cache.  If adding a record would cause the cache to exceed this size, the
     *     resource record closest to expiration is removed before adding the new resource record, thus capping the cache's size.  The minimum cache size is 1,000 resource
     *     records.  Any attempt to set a cache size smaller than that is silently changed to 1,000 resource records.</li>
     *     <li>_maxAllowableTTLMillis - the maximum time, in milliseconds, that a resource record may remain cached - no matter what the TTL on the resource record is.  To
     *     prevent capping the TTL, set this value to {@link Long#MAX_VALUE}.  Values must be greater than zero.</li>
     * </ul>
     *
     * @param _maxCacheSize The maximum number of DNS resource records that may be stored in this cache.
     * @param _maxAllowableTTLMillis The maximum time, in milliseconds, that any resource record is allowed to exist before expiring.
     * @param _rootHints The {@link DNSRootHints} manager to use for recursive resolution.
     */
    public DNSCache( final int _maxCacheSize, final long _maxAllowableTTLMillis, final DNSRootHints _rootHints ) {

        Checks.required( _rootHints );

        // sanity check...
        if( _maxAllowableTTLMillis < 1 )
            throw new IllegalArgumentException( "Invalid max allowable timeout: " + _maxAllowableTTLMillis );

        maxCacheSize          = _maxCacheSize;
        maxAllowableTTLMillis = Math.max( MIN_CACHE_SIZE, _maxAllowableTTLMillis );
        entryMap              = new HashMap<>( maxCacheSize );
        ttlMap                = new TreeMap<>();
        uniqueInteger         = new AtomicLong();
        rootHints             = _rootHints;

        LOGGER.log( FINE, "Created DNSCache, max size " + maxCacheSize + " DNS resource records" );
    }


    /**
     * Creates a new instance of this class with a maximum of 5,000 cached resource records, a maximum allowable TTL of two hours, and a default {@link DNSRootHints} instance.
     */
    @SuppressWarnings( "unused" )
    public DNSCache() {
        this( DEFAULT_MAX_CACHE_SIZE, DEFAULT_MAX_ALLOWABLE_TTL_MILLIS, new DNSRootHints() );
    }


    /**
     * Attempts to resolve the given query message, and returns the result in a synthetic response message.  Failure to resolve from the cache is indicated by a response code of
     * {@link DNSResponseCode#NAME_ERROR}.  The intent of this method is to provide results from the cache, if possible, that closely resemble the results of the same query
     * message sent to a DNS server.  The results are quite different depending on whether the query message requests recursion:
     * <ul>
     *     <li>Recursion requested: The cache is searched for the answers to the question contained in the query.  If the cache contains an answer to the question in the query
     *     (including resolving any CNAME chain), then the response code is {@link DNSResponseCode#OK} and the answers contain the resource records found.  Otherwise, the
     *     response code is {@link DNSResponseCode#NAME_ERROR} and no resource records are returned.</li>
     *     <li>No recursion requested: First the cache is searched for the answers to the question contained in the query.  If the cache contains an answer to the question in
     *     the query (including resolving any CNAME chain), then the response code is {@link DNSResponseCode#OK} and the answers contain the resource records found.  Otherwise,
     *     the cache is searched for the most specific name server entries it can find.  At worst case, this will be the root name servers (from the root hints file).  If the
     *     cache has more specific name server entries, they will be used.  For example, if the original question was for A records from "www.bogus.com", and the cache had
     *     no such records, first it will search for name servers for "bogus.com", then for "com", and only if both of those have no results will it return the root name
     *     servers.  In all cases, the response code will be {@link DNSResponseCode#OK}, there will be no answers, the name servers found will be in the authorities, and if
     *     the IP addresses of the name servers are in the cache, they will be in the additional records.</li>
     * </ul>
     * Note that if the query is somehow malformed, the response code will be {@link DNSResponseCode#FORMAT_ERROR}, and there will be no answers, authorities, or additional
     * records.
     *
     * @param _queryMessage The {@link DNSMessage} containing the query to be resolved (if possible) from the cache.
     * @return The {@link DNSMessage} containing the result of the attempted resolution from cache.
     */
    public DNSMessage resolve( final DNSMessage _queryMessage ) {

        Checks.required( _queryMessage );

        // if the query message isn't a valid query, return a FORMAT_ERROR...
        if( _queryMessage.isResponse || (_queryMessage.questions.size() == 0) || (_queryMessage.getQuestion().qtype == DNSRRType.UNIMPLEMENTED) )
            return _queryMessage.getSyntheticNotOKResponse( FORMAT_ERROR );

        // if the query is for type ANY, we'll fail, because we can't tell if the cache has all records...
        if( _queryMessage.getQuestion().qtype == ANY )
            return _queryMessage.getSyntheticNotOKResponse( NAME_ERROR );

        // if we can resolve this query from the cache, return the response with all the answers...
        List<DNSResourceRecord> answers = resolveAnswers( _queryMessage.getQuestion() );
        if( answers.size() > 0 )
            return _queryMessage.getSyntheticOKResponse( answers );

        // since we don't have any answers, if the query requested recursion, we leave with a NAME_ERROR...
        if( _queryMessage.recurse )
            return _queryMessage.getSyntheticNotOKResponse( NAME_ERROR );

        // if we get here, then we're answering without recursion, and we couldn't directly resolve the query - time to look for name servers...
        DNSDomainName nsSearchDomain = _queryMessage.getQuestion().qname.parent();
        List<DNSResourceRecord> nameServers;
        do {
            nameServers = resolveAnswers( new DNSQuestion( nsSearchDomain, NS ) );
            if( nsSearchDomain.isRoot() && (nameServers.size() == 0) ) {
                if( !updateRootHints() )
                    return _queryMessage.getSyntheticNotOKResponse( SERVER_FAILURE );
            }
            else
                nsSearchDomain = nsSearchDomain.parent();
        } while( nameServers.size() == 0 );

        // if we get here, we have at least one name server, and possibly some CNAME records - filter them out...
        nameServers = nameServers.stream().filter( (rr) -> rr.type == NS ).collect( Collectors.toList());

        // let's see if we have cached IP addresses for those name servers...
        List<DNSResourceRecord> nameServersIPs = new ArrayList<>();
        nameServers.forEach( (ns) -> {
            DNSDomainName nsdn = ((com.dilatush.dns.rr.NS)ns).nameServer;

        } );
    }


    private boolean updateRootHints() {
        Outcome<List<DNSResourceRecord>> rho = rootHints.current();
        if( rho.notOk() ) {
            LOGGER.log( SEVERE, "Cannot get current root hints: " + rho.msg(), rho.cause() );
            return false;
        }
        add( rho.info() );
        return true;
    }


    /**
     * Attempt to find answers in the cache for the given question, including resolving any CNAME chain.  If answers are found, the returned list of resource records contains
     * them (including any CNAME chain).  Otherwise, an empty list is returned.
     *
     * @param _question The question to be resolved from cache.
     * @return The answers found in the cache, which may be none.
     */
    public List<DNSResourceRecord> resolveAnswers( final DNSQuestion _question ) {

        Checks.required( _question );

        // make a place to stuff our answers...
        List<DNSResourceRecord> answers = new ArrayList<>();

        // get anything the cache might have from the domain we're looking for...
        List<DNSResourceRecord> cached = get( _question.qname );

        // if we got nothing at all back, bail out negatively...
        if( cached.size() == 0 )
            return answers;

        // iterate over the cached records to see if any of them match what we're looking for, or match a CNAME that might point to what we need...
        cached.forEach( (rr) -> {

            // if the cached record matches the class and type in the question, stuff it directly into the answers...
            if( (rr.klass == _question.qclass) && (rr.type == _question.qtype) )
                answers.add( rr );

            // if it's a CNAME, and it's the only record we got, then we need to resolve the chain (which could be arbitrarily long)...
            // (if there's a CNAME, the DNS RFCs call for it to be the ONLY resource record with that FQDN)...
            else if( (rr.type == CNAME) && (cached.size() == 1) ) {

                // follow the CNAME chain to its end, recording the CNAMEs into the cname chain...
                List<DNSResourceRecord> cnameChain = new ArrayList<>();            // a place to store our chain of CNAMEs...
                List<DNSResourceRecord> chainCache = new ArrayList<>( cached );    // the cached results as we follow the chain...

                // so long as what we found is a valid CNAME chain element, add it to our CNAME chain and move to the next element...
                while( (chainCache.size() == 1) && (chainCache.get(0).type == CNAME) ) {
                    cnameChain.add( chainCache.get( 0 ) );
                    com.dilatush.dns.rr.CNAME cnameRR = (com.dilatush.dns.rr.CNAME)chainCache.get( 0 );
                    chainCache = get( cnameRR.cname );
                }

                // at this point, the CNAME chain contains 1 or more CNAME records, and the chain cache contains a different kind of record, or no record -
                // so now we see if the chain cache has any of the kinds of records we actually want, and if so we add them to the CNAME chain...
                int startSize = cnameChain.size();   // remember how big the CNAME chain was before we started...
                chainCache.stream()
                        .filter(  (arr) -> (arr.klass == _question.qclass) && (arr.type == _question.qtype) )
                        .forEach( cnameChain::add );

                // if we got at least one of the record type we actually want, then dump the CNAME chain into our answers...
                if( startSize < (cnameChain).size() )
                    answers.addAll( cnameChain );
            }
        } );

        return answers;
    }


    /**
     * <p>Adds the given {@link DNSResourceRecord} to this cache with the given expiration time (using system time as returned by {@link System#currentTimeMillis()}).  Attempts
     * to add expired or {@link UNIMPLEMENTED} resource records are silently ignored.  The actual expiration time used in the cache is calculated as the earlier of the given
     * expiration time or the current time plus the maximum allowable TTL.  </p>
     * <p>If the cache already contains the maximum number of cache entries allowed, then the cached record with the earliest expiration time is purged before adding the new
     * resource record, thus capping the cache's size. </p>
     * <p>If there is already an entry in the cache that is of the same type as the entry to be added, with the same resource record data, then the existing entry is overwritten
     * with the new entry.  For instance, if the cache of resource records for "www.bogus.com" already had an A record with "141.2.3.76", and a new matching A record was added,
     * the new record will overwrite the existing on.  The main significance of this behavior is that it is possible for the TTL of a resource record in the cache to be updated.</p>
     * <p>If the cache does not contain any resource records that are the same type with the same resource record data as the resource record being added, then the new resource
     * record is added to the cache.</p>
     *
     * @param _rr The {@link DNSResourceRecord} to be added to this cache.
     * @param _expires The system time that this record expires.
     */
    public synchronized void add( final DNSResourceRecord _rr, final long _expires ) {

        Checks.required( _rr );

        // if the TTL on the given record is zero, we're not going to cache it...
        if( _rr.ttl == 0 )
            return;

        // we aren't going to add unimplemented resource records...
        if( _rr instanceof UNIMPLEMENTED )
            return;

        // if the given resource record is already expired, just leave - we don't want it in the cache...
        if( _expires <= System.currentTimeMillis() )
            return;

        LOGGER.log( FINE, "Adding to cache: " + _rr + "(" + ttlMap.size() + " resource records cached before this addition)" );

        // if the expiration time is too far into the future, truncate it...
        long expires = Math.min( _expires, System.currentTimeMillis() + maxAllowableTTLMillis );

        // if we don't have an entry for this domain, we need to add one...
        if( !entryMap.containsKey( _rr.name.text ) )
            entryMap.put( _rr.name.text, new DNSCacheEntry[0] );

        // if we already have an entry that matches the class, type, and resource data then we're going to replace that one...
        DNSCacheEntry[] entries = entryMap.get( _rr.name.text );  // this is guaranteed to be non-null because of the code just above...

        // iterate over all the entries looking for a resource record that's the same (domain, class, type, resource data) as the one being added...
        // exiting the loop with entryIndex >= entries.length means we found no resource records that are the same...
        int entryIndex;
        for( entryIndex = 0; entryIndex < entries.length; entryIndex++ ) {

            DNSCacheEntry entry = entries[entryIndex];

            // if this entry isn't the same as the record being added, we try the next one...
            if( !entry.resourceRecord.sameAs( _rr ) )
                continue;

            // if we get here, then the current entry is the same as the added record...
            // that means we need to overwrite this entry with the (presumably "fresher") record we're adding...

            LOGGER.log( FINE, "Overwriting: " + entry.resourceRecord );

            // remove the to-be-overwritten record's mapping in ttlMap...
            ttlMap.remove( entry.ttlKey );

            // make a new key for the mapping in ttlMap, for the new entry we'll be making there...
            DNSTTLCacheKey ttlKey = new DNSTTLCacheKey( expires, uniqueInteger.getAndIncrement() );

            // make a new cache entry for the record we're adding, overwriting the existing record...
            entries[entryIndex] = new DNSCacheEntry( _rr, ttlKey );

            // make the new mapping in ttlMap for the record we're adding
            ttlMap.put( ttlKey, entries[entryIndex] );

            // no need to check for other matches; this logic guarantees there will be at most one match in a given domain...
            // entryMap already has a reference to this array, so we don't need to update the entryMap mapping...
            break;
        }

        // if the entryIndex >= entries.length, then we don't already have a record that same as the one we're adding...
        // that means we have to actually add a new one after making room for it...
        if( entryIndex >= entries.length ) {

            // if our cache would have too many entries with this addition, trim it down...
            while( ttlMap.size() >= maxCacheSize ) {

                // remove the ttl entry closest to expiring...
                remove( ttlMap.firstEntry().getValue() );
            }

            // make a new array that's one longer than the existing one, and copy the existing elements into it...
            DNSCacheEntry[] newEntries = Arrays.copyOf( entries, entries.length + 1 );

            // make a key for the new mapping we need to make in ttlMap...
            DNSTTLCacheKey ttlKey = new DNSTTLCacheKey( expires, uniqueInteger.getAndIncrement() );

            // calculate the index to where we'll be stuffing our new record...
            int newEntryIndex = newEntries.length - 1;

            // create the new cache entry and stuff it away...
            newEntries[newEntryIndex] = new DNSCacheEntry( _rr, ttlKey );

            // make the new mapping in ttlMap for the record we're adding...
            ttlMap.put( ttlKey, newEntries[newEntryIndex] );

            // update the domain mapping in entryMap with our newly expanded entries...
            entryMap.put( _rr.name.text, newEntries );
        }
    }


    /**
     * <p>Adds the given {@link DNSResourceRecord} to this cache with the expiration time calculated from the resource record's TTL.  Any attempt to add a {@code null} resource
     * record is logged and ignored.  Attempts to add expired or {@link UNIMPLEMENTED} resource records are silently ignored.  The actual expiration time used in the cache is
     * calculated as the earlier of the calculated expiration time or the current time plus the maximum allowable TTL.  </p>
     * <p>If the cache already contains the maximum number of cache entries allowed, then the cached record with the earliest expiration time is purged before adding the new
     * resource record, thus capping the cache's size. </p>
     * <p>If there is already an entry in the cache that is of the same type as the entry to be added, with the same resource record data, then the existing entry is overwritten
     * with the new entry.  For instance, if the cache of resource records for "www.bogus.com" already had an A record with "141.2.3.76", and a new matching A record was added,
     * the new record will overwrite the existing on.  The main significance of this behavior is that it is possible for the TTL of a resource record in the cache to be updated.</p>
     * <p>If the cache does not contain any resource records that are the same type with the same resource record data as the resource record being added, then the new resource
     * record is added to the cache.</p>
     *
     * @param _rr The {@link DNSResourceRecord} to be added to this cache.
     */
    public void add( final DNSResourceRecord _rr ) {

        Checks.required( _rr );

        add( _rr, System.currentTimeMillis() + (_rr.ttl * 1000) );
    }


    /**
     * <p>Adds the given {@link DNSResourceRecord}s to this cache with the expiration time calculated from each resource record's TTL.  Any attempt to add a {@code null} resource
     * record is logged and ignored.  Attempts to add expired or {@link UNIMPLEMENTED} resource records are silently ignored.  The actual expiration time used in the cache is
     * calculated as the earlier of the calculated expiration time or the current time plus the maximum allowable TTL.  </p>
     * <p>If the cache already contains the maximum number of cache entries allowed, then the cached record with the earliest expiration time is purged before adding each new
     * resource record, thus capping the cache's size. </p>
     * <p>If there is already an entry in the cache that is of the same type as an entry to be added, with the same resource record data, then the existing entry is overwritten
     * with the new entry.  For instance, if the cache of resource records for "www.bogus.com" already had an A record with "141.2.3.76", and a new matching A record was added,
     * the new record will overwrite the existing on.  The main significance of this behavior is that it is possible for the TTL of a resource record in the cache to be updated.
     * </p>
     * <p>If the cache does not contain any resource records that are the same type with the same resource record data as a resource record being added, then the new resource
     * record is added to the cache.</p>
     *
     * @param _rrs The list of {@link DNSResourceRecord}s to be added to this cache.
     */
    public void add( final List<DNSResourceRecord> _rrs ) {

        Checks.required( _rrs );

        _rrs.forEach( this::add );
    }


    /**
     * Returns a list of all the unexpired {@link DNSResourceRecord}s held in this cache for the given fully-qualified domain name (FQDN).  If the cache holds no resource records
     * for the given domain, then an empty list is returned.
     *
     * @param _dn The FQDN to retrieve resource records for.
     * @return The (possibly empty) list of retrieved records.
     */
    public synchronized List<DNSResourceRecord> get( final String _dn ) {

        Checks.required( _dn );

        // get the entries for this FQDN, or null if there are none...
        DNSCacheEntry[] entries = entryMap.get( _dn.toLowerCase() );

        // if we have no entries for this FQDN, then we just return an empty list...
        if( entries == null ) {
            LOGGER.log( FINE, "Cache miss for " + _dn.toLowerCase() );
            return new ArrayList<>( 0 );
        }

        // we have some candidate entries, so long as they haven't expired, so make a list to hold the results...
        List<DNSResourceRecord> result = new ArrayList<>( entries.length );

        // record the current time (so we can check for expired records)...
        long currentTime = System.currentTimeMillis();

        // iterate over all the entries to look for the ones that belong in the results...
        for( DNSCacheEntry entry : entries ) {

            // if the entry has expired, remove it and of course don't return it...
            if( entry.expiration < currentTime ) {
                remove( entry );
                continue;
            }

            // it's a valid record, so add it to our list...
            result.add( entry.resourceRecord );
        }

        // at last, at last!  we're done; return with the results (which could be empty if all the records we had were expired)...
        LOGGER.log( FINE, "Cache hit for " + _dn.toLowerCase() + "\n" + DNSUtil.toString( result ) );
        return result;
    }


    /**
     * Returns a list of all the unexpired {@link DNSResourceRecord}s held in this cache for the given {@link DNSDomainName}.  If the cache holds no resource records
     * for the given domain, then an empty list is returned.
     *
     * @param _dn The {@link DNSDomainName} to retrieve resource records for.
     * @return The (possibly empty) list of retrieved records.
     */
    public List<DNSResourceRecord> get( final DNSDomainName _dn ) {
        return get( _dn.text );
    }


    /**
     * Returns a list of all the unexpired {@link DNSResourceRecord}s held in this cache for the given domain name whose record type matches one of the given types.
     * If the cache holds no matching records, then an empty list is returned.
     *
     * @param _dn The domain name to retrieve resource records for.
     * @param _types The types of resource records wanted.
     * @return The (possibly empty) list of retrieved records.
     */
    public List<DNSResourceRecord> get( final String _dn, DNSRRType... _types ) {

        Checks.required( _dn, _types );

        return filterResourceRecords( get( _dn ), _types );
    }


    /**
     * Returns a list of all the unexpired {@link DNSResourceRecord}s held in this cache for the given {@link DNSDomainName} whose record type matches one of the given types.
     * If the cache holds no matching records, then an empty list is returned.
     *
     * @param _dn The {@link DNSDomainName} to retrieve resource records for.
     * @param _types The types of resource records wanted.
     * @return The (possibly empty) list of retrieved records.
     */
    public List<DNSResourceRecord> get( final DNSDomainName _dn, DNSRRType... _types ) {

        Checks.required( _dn, _types );
        return get( _dn.text, _types );
    }


    /**
     * Returns the number of resource records currently held in this cache.  Note that some of these records may have expired.
     *
     * @return The number of resource records currently held in this cache.
     */
    public synchronized int size() {
        return ttlMap.size();
    }


    /**
     * Clear this cache.  After this call, the cache will be completely empty, exactly as if it had just been constructed.
     */
    public synchronized void clear() {
        entryMap.clear();
        ttlMap.clear();
        uniqueInteger.set( 0 );
    }


    /**
     * Remove the given {@link DNSCacheEntry} from this cache.  In practical terms, this means removing it from both cache maps.
     *
     * @param _dce The {@link DNSCacheEntry} to remove.
     */
    private void remove( final DNSCacheEntry _dce ) {

        LOGGER.log( FINE, "Removing from cache: " + _dce.resourceRecord );

        // first remove the entry from the ttl map, using the handy-dandy key that we squirreled away...
        ttlMap.remove( _dce.ttlKey );

        // then remove it from the entry map...

        // first get the entries for this FQDN...
        DNSCacheEntry[] entries = entryMap.get( _dce.resourceRecord.name.text );

        // if there were no entries, then there's nothing to remove; shouldn't happen, but if somehow it does, just leave...
        if( entries == null )
            return;

        // iterate over all the entries, looking for the one we're trying to remove...
        int entryIndex;
        for( entryIndex = 0; entryIndex < entries.length; entryIndex++ ) {

            DNSCacheEntry entry = entries[entryIndex];

            // if the entry is the same object (not equal to, but the object identity), then we've found the one we want to purge...
            if( entry == _dce ) {

                // if this was the last entry for this FQDN, then we'll just remove this mapping from the entryMap, and we're done...
                if( entries.length == 1 ) {
                    entryMap.remove( _dce.resourceRecord.name.text );
                    return;
                }

                // there's more than one entry for this FQDN, so now we've got to shrink them...

                // first we make our new entries, one shorter than the old entries...
                DNSCacheEntry[] newEntries = new DNSCacheEntry[entries.length - 1];

                // if there were entries at lower indices than the one we're removing, copy them over...
                if( entryIndex > 0 )
                    System.arraycopy( entries, 0, newEntries, 0, entryIndex );

                // if there were entries at higher indices than the one we're removing, copy them over...
                if( entryIndex < (entries.length - 1) )
                    System.arraycopy( entries, entryIndex + 1, newEntries, entryIndex, newEntries.length - entryIndex );

                // map our new entries into place, and we're finished...
                entryMap.put( _dce.resourceRecord.name.text, newEntries );
                return;
            }
        }

        // we really should never get here, but if we do it means we didn't find the resource record we're trying to remove...
        // in that case, we just hang our head and leave...
    }


    /**
     * Instances of this class are used as keys to the {@link DNSCache} {@code ttlMap}; they are immutable and threadsafe.  The key is effectively a 128-bit integer.  The
     * high-order 64 bits are the local system time (as returned by {@link System#currentTimeMillis()}) that this cache entry will expire.  The low-order 64 bits are a unique
     * integer within this cache.  Instances of this class are immutable and threadsafe.
     */
    public static class DNSTTLCacheKey implements Comparable<DNSTTLCacheKey> {

        /** The expiration time as a system time (like {@link System#currentTimeMillis()}). */
        public final long expiration;

        /** The discriminator, which is simply a unique integer (unique over all the {@link DNSTTLCacheKey} instances in this cache). */
        public final long discriminator;


        /**
         * Creates a new instance of this class using the given arguments.  Note that this class makes no attempt to verify that the discriminator is unique, nor does it
         * check the expiration time for validity.
         *
         * @param _expiration The expiration time as a system time (like {@link System#currentTimeMillis()}).
         * @param _uniqueInteger The discriminator, which is simply a unique integer (unique over all the {@link DNSTTLCacheKey} instances in this cache).
         */
        public DNSTTLCacheKey( final long _expiration, final long _uniqueInteger ) {

            expiration    = _expiration;
            discriminator = _uniqueInteger;
        }


        /**
         * Returns {@code true} if this object is equal to the given object.
         *
         * @param _o The object to test for equality to this object.
         * @return {@code true} if this object is equal to the given object.
         */
        @Override
        public boolean equals( final Object _o ) {

            // if the given object is the same instance as this object, then obviously they're equal...
            if( this == _o ) return true;

            // if the given object is of a different class than this object, then obviously they're not equal...
            if( _o == null || getClass() != _o.getClass() ) return false;

            // our DNSTTLCacheKey instances are equal only if their expirations and discriminators are equal...
            DNSTTLCacheKey that = (DNSTTLCacheKey) _o;
            return (expiration == that.expiration ) && (discriminator == that.discriminator );
        }


        /**
         * Returns a hash code for this object.
         *
         * @return a hash code for this object.
         */
        @Override
        public int hashCode() {

            return Objects.hash( expiration, discriminator );
        }


        /**
         * Returns a negative integer, zero, or positive integer as this instance is less than, equal to, or greater than the given instance.  The comparison is computed as if
         * {@link #expiration} were the 64 high-order bits and {@link #discriminator} were the 64 low-order bits of a 128-bit integer.
         *
         * @param _other the {@link DNSTTLCacheKey} to compare with this instance.
         * @return a negative integer, zero, or positive integer as this instance is less than, equal to, or greater than the given instance.
         */
         @Override
        public int compareTo( final DNSTTLCacheKey _other ) {

            int c = Long.compare( expiration, _other.expiration );
            return ( c != 0 ) ? c : Long.compare( discriminator, _other.discriminator );
        }
    }


    /**
     * Instances of this class are the actual entries in a {@link DNSCache}.  Basically this class wraps a {@link DNSResourceRecord} together with an expiration time
     * and the key to this record's mapping in {@link #ttlMap}.  Instances of this class are immutable and threadsafe.
     */
    public static class DNSCacheEntry {

        /** The {@link DNSResourceRecord} for this entry. */
        public final DNSResourceRecord resourceRecord;

        /** The expiration time for this entry, in system time (like {@link System#currentTimeMillis()}). */
        public final Long expiration;

        /** The {@link DNSTTLCacheKey} for this entry. */
        public final DNSTTLCacheKey ttlKey;


        /**
         * Create a new instance of this class with the given resource record and cache key.
         *
         * @param _resourceRecord The {@link DNSResourceRecord} to be included in this cache entry.
         * @param _ttlKey The {@link DNSTTLCacheKey} to be included in this cache entry.
         */
        public DNSCacheEntry( final DNSResourceRecord _resourceRecord, final DNSTTLCacheKey _ttlKey ) {

            Checks.required( _resourceRecord, _ttlKey );

            resourceRecord = _resourceRecord;
            expiration     = System.currentTimeMillis() + (_resourceRecord.ttl * 1000);
            ttlKey         = _ttlKey;
        }


        /**
         * Returns a string representation of this instance.
         *
         * @return The string representation of this instance.
         */
        @Override
        public String toString() {
            return resourceRecord.toString();
        }
    }
}
