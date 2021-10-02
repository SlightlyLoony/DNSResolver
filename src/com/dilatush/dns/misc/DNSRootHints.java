package com.dilatush.dns.misc;

import com.dilatush.dns.message.DNSDomainName;
import com.dilatush.dns.rr.A;
import com.dilatush.dns.rr.AAAA;
import com.dilatush.dns.rr.DNSResourceRecord;
import com.dilatush.dns.rr.NS;
import com.dilatush.util.Checks;
import com.dilatush.util.Outcome;
import com.dilatush.util.Streams;

import java.io.IOException;
import java.io.InputStream;
import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static com.dilatush.util.General.getLogger;
import static com.dilatush.util.General.isNull;
import static java.util.regex.Pattern.MULTILINE;
import static java.util.regex.Pattern.compile;

/**
 * <p>Instances of this class manage DNS root name server "hints".  These are publicly downloadable via HTTP.  Methods are provided to read and write a local file (to provide
 * persistence, mainly for startup), to read the original file via HTTP, and to cache the results locally.</p>
 * <p>The TTLs for decoded root hints (which are lists of {@link DNSResourceRecord}s) are adjusted according to the source:</p>
 * <ul>
 *     <li>When the root hints are read from local storage (essentially a cache of the last download), the TTLs are calculated from the file's last modified time.</li>
 *     <li>When the root hints are downloaded from the web, the TTLs are calculated from the download time.</li>
 * </ul>
 */
@SuppressWarnings( "unused" )
public class DNSRootHints {

    private static final Logger LOGGER = getLogger();

    private static final String DEFAULT_ROOT_HINTS_FILE_NAME  = "ROOT_HINTS.TXT";
    private static final String DEFAULT_ROOT_HINTS_URL_STRING = "https://www.internic.net/domain/named.root";

    private static final Pattern RR_PATTERN   = compile( "^((?:[A-Z-]*\\.)+) +([1-9][0-9]+) +(A|AAAA|NS) +([^ ]*)$", MULTILINE );

    private static final Outcome.Forge<?>                       outcome          = new Outcome.Forge<>();
    private static final Outcome.Forge<RootHintsSource>         rootHintsOutcome = new Outcome.Forge<>();
    private static final Outcome.Forge<List<DNSResourceRecord>> rrlOutcome       = new Outcome.Forge<>();
    private static final Outcome.Forge<DNSResourceRecord>       rrOutcome        = new Outcome.Forge<>();

    private final String urlString;
    private final String rootHintsFileName;

    // this always contains the most recently read version, whether from file or URL...
    private RootHintsSource rootHints;


    /**
     * Creates a new instance of this class with the given URL and root hints file name.
     *
     * @param _urlString The URL to find the root hints file at.
     * @param _rootHintsFileName The name (and path) of the root hints file.
     */
    public DNSRootHints( final String _urlString, final String _rootHintsFileName ) {

        Checks.required( _urlString, _rootHintsFileName );

        urlString = _urlString;
        rootHintsFileName = _rootHintsFileName;
    }


    /**
     * Creates a new instance of this class with the default URL and root hints file name.
     */
    public DNSRootHints() {
        this( DEFAULT_ROOT_HINTS_URL_STRING, DEFAULT_ROOT_HINTS_FILE_NAME );
    }


    /**
     * Read the root hints ASCII-encoded text from the URL.  If the outcome is ok, an instance of {@link RootHintsSource} is created, with a string containing the root hints
     * text and a download time of the current system time in milliseconds.  If the outcome is not ok, then the outcome's message will contain an explanation.
     *
     * @return the {@link Outcome Outcome&lt;RootHintsSource&gt;} result.
     */
    private Outcome<RootHintsSource> readURL() {

        try {

            // get an input stream from the URL...
            InputStream is = new URL( urlString ).openStream();

            // read the stream and use it to make our root hints source instance...
            rootHints = new RootHintsSource( Streams.toString( is, StandardCharsets.US_ASCII ), System.currentTimeMillis());
            LOGGER.finer( "Read root hints from URL: " + urlString );

            // all is ok...
            return rootHintsOutcome.ok( rootHints );
        }

        // we don't want no stinkin' I/O exceptions...
        catch( IOException _e ) {

            // let the caller know what things went wrong...
            LOGGER.log( Level.WARNING, "Problem reading URL: " + _e.getMessage(), _e );
            return rootHintsOutcome.notOk(
                    "Problem reading URL: " + _e.getMessage(),
                    new DNSResolverException( "Problem reading root hints URL", _e, DNSResolverError.ROOT_HINTS_PROBLEMS )
            );
        }
    }


    /**
     * Read the root hints file from the local file system as ASCII-encoded text.  If the outcome is ok, an instance of {@link RootHintsSource} is created, with a string
     * containing the root hints text and a download time equal to the last time the file was modified.  If the outcome is not ok, then the outcome's message will contain an
     * explanation.
     *
     * @return the {@link Outcome Outcome&lt;RootHintsSource&gt;} result.
     */
    private Outcome<RootHintsSource> readFile() {

        try {

            // if we don't have a usable file, return not ok...
            Path rhPath = Path.of( rootHintsFileName );
            if( !Files.exists( rhPath ) || !Files.isReadable( rhPath ) || (Files.size( rhPath ) < 500 ) ) {

                // we won't be too specific, as this really isn't very likely - if we could write it, then we really should be able to write it...
                return rootHintsOutcome.notOk(
                        "Root hints file does not exist, is not readable, or is too short to be valid",
                        new DNSResolverException( "Can't read root hints file", DNSResolverError.ROOT_HINTS_PROBLEMS )
                );
            }

            // ok, it's safe to actually read it...
            rootHints = new RootHintsSource( Files.readString( rhPath, StandardCharsets.US_ASCII ), Files.getLastModifiedTime( rhPath ).toMillis() );
            LOGGER.finer( "Read root hints from file: " + rootHintsFileName );

            // all is ok...
            return rootHintsOutcome.ok( rootHints );
        }

        // oh, oh, something went horribly wrong...
        catch( IOException _e ) {
            LOGGER.log( Level.WARNING, "Problem reading root hints file: " + _e.getMessage(), _e );
            return rootHintsOutcome.notOk(
                    "Problem reading root hints file: " + _e.getMessage(),
                    new DNSResolverException( "Problem reading root hints file", _e, DNSResolverError.ROOT_HINTS_PROBLEMS )
            );
        }
    }


    /**
     * Write the given root hints string to the local file system as ASCII-encoded text.
     *
     * @param _rootHints The root hints source.
     * @return the {@link Outcome Outcome&lt;?&gt;} result of the write operation.
     */
    private Outcome<?> writeFile( final RootHintsSource _rootHints ) {

        try {

            // look ma, we can do all this with one line of code these days...
            Files.writeString( Path.of( rootHintsFileName ), _rootHints.rootHints, StandardCharsets.US_ASCII );
            LOGGER.finer( "Wrote root hints file: " + rootHintsFileName );

            // all is ok...
            return outcome.ok();
        }

        // dang it, something didn't work...
        catch( IOException _e ) {
            LOGGER.log( Level.WARNING, "Problem writing root hints file: " + _e.getMessage(), _e );
            return outcome.notOk(
                    "Problem writing root hints file: " + _e.getMessage(),
                    new DNSResolverException( "Problem writing root hints file", _e, DNSResolverError.ROOT_HINTS_PROBLEMS )
            );
        }
    }


    /**
     * Decode the most recently read root hints file into a list of resource records.
     *
     * @return the {@link Outcome Outcome&lt;List&lt;DNSResourceRecord&gt;&gt;} result of this operation.
     */
    private Outcome<List<DNSResourceRecord>> decode() {

        // verify that we actually HAVE some root hints...
        if( isNull( rootHints ) )
            return rrlOutcome.notOk(
                    "No root hints have been read", new DNSResolverException( "No root hints have been read", DNSResolverError.ROOT_HINTS_PROBLEMS )
            );

        // decode the three possible types of records in the root hints file: NS, A, and AAAA...
        List<DNSResourceRecord> entries = new ArrayList<>();

        // regex for the win, matching the text of each resource record entry...
        Matcher mat = RR_PATTERN.matcher( rootHints.rootHints );
        while( mat.find() ) {

            // extract the pieces of the current resource records string...
            String dnStr  = mat.group( 1 );  // the domain name...
            String ttlStr = mat.group( 2 );  // the time-to-live...
            String rrtStr = mat.group( 3 );  // the resource record type ("A", "AAAA", or "NS")...
            String rrdStr = mat.group( 4 );  // the resource record data...

            // validate the domain name...
            Outcome<DNSDomainName> dno = DNSDomainName.fromString( dnStr );
            if( dno.notOk() )
                return rrlOutcome.notOk( "Could not decode '" + dnStr + "' as a domain name: " + dno.msg(), dno.cause() );
            DNSDomainName dn = dno.info();

            // Calculate the TTL based on the download time, not the current time.  Note that the resource record specifies the TTL in seconds, not milliseconds,
            // so we have to adjust for that.  If we calculate a TTL less than 1 millisecond, then it has expired and we need to re-read the URL...
            int ttlBase = Integer.parseInt( ttlStr );  // should be impossible to throw NumberFormatException...
            long longTTL = rootHints.downloadTimeMillis + (ttlBase * 1000L) - System.currentTimeMillis();

            // if we've expired, we're not going to decode any records; we'll return with an error...
            if( longTTL < 1 ) {
                LOGGER.finer( "Root hints entries have expired" );
                return rrlOutcome.notOk( "Root hints entries have expired" );
            }

            // get the seconds from the milliseconds, and check that it's not too large to fit in 32 bits...
            longTTL /= 1000;
            if( (longTTL & 0xFFFFFFFF00000000L) != 0 ) {
                LOGGER.finer( "TTL in root hints is too large: " + longTTL );
                return rrlOutcome.notOk( "TTL in root hints is too large: " + longTTL );
            }

            // get our ttl into an integer, ready for making a resource record instance...
            int ttl = (int)longTTL;

            // there are only three possible values here: "A", "AAAA", or "NS"...
            Outcome<DNSResourceRecord> rro = switch( rrtStr ) {

                case "A" -> {

                    try {
                        // get the bare IP address...
                        InetAddress address = InetAddress.getByName( rrdStr );

                        // add the domain name to it...
                        address = InetAddress.getByAddress( dnStr, address.getAddress() );

                        // get the resource record instance...
                        Outcome<A> iao = A.create( dn, ttl, (Inet4Address) address );

                        // report the result...
                        yield iao.ok()
                                ? rrOutcome.ok( iao.info() )
                                : rrOutcome.notOk( "Problem creating A resource record: " + iao.msg(), iao.cause() );
                    }

                    // this really shouldn't happen unless somehow the root hints have a malformed IP address string...
                    catch( Exception _e ) {
                        yield rrOutcome.notOk( "Problem creating A resource record: " + _e.getMessage(), _e );
                    }
                }

                case "AAAA" -> {

                    try {
                        // get the bare IP address...
                        InetAddress address = InetAddress.getByName( rrdStr );

                        // add the domain name to it...
                        address = InetAddress.getByAddress( dnStr, address.getAddress() );

                        // get the resource record instance...
                        Outcome<AAAA> iao = AAAA.create( dn, ttl, (Inet6Address) address );

                        // report the result...
                        yield iao.ok()
                                ? rrOutcome.ok( iao.info() )
                                : rrOutcome.notOk( "Problem creating AAAA resource record: " + iao.msg(), iao.cause() );
                    }

                    // this really shouldn't happen unless somehow the root hints have a malformed IP address string...
                    catch( Exception _e ) {
                        yield rrOutcome.notOk( "Problem creating AAAA resource record: " + _e.getMessage(), _e );
                    }
                }

                case "NS" -> {

                    // get the domain name of the name server...
                    Outcome<DNSDomainName> nsdno = DNSDomainName.fromString( rrdStr );

                    // this could only be "not ok" if somehow the root hints have a malformed domain name...
                    if( nsdno.notOk() )
                        yield rrOutcome.notOk( nsdno.msg(), nsdno.cause() );

                    // get the resource record instance...
                    Outcome<NS> nso = NS.create( dn, ttl, nsdno.info() );

                    // report the result...
                    yield nso.ok()
                            ? rrOutcome.ok( nso.info() )
                            : rrOutcome.notOk( nso.msg(), nso.cause() );
                }
            };

            // if creating any resource record fails, we'll fail the whole thing...
            if( rro.notOk() )
                return rrlOutcome.notOk( rro.msg(), rro.cause() );

            // we got a good resource record, so add it to our results...
            entries.add( rro.info() );
        }

        // and we're done...
        return rrlOutcome.ok( entries );
    }


    /**
     * Returns a list of resource records in the current root hints file.  This method will first attempt to read the local root hints file.  If that fails, or if the entries have
     * expired, it will read the latest root hints from the URL, update the local file, and return the fresh root hints from that.  If all of those efforts fail, it will return an
     * error.
     *
     * @return the {@link Outcome Outcome&lt;List&lt;DNSResourceRecord&gt;&gt;} result of this operation.
     */
    public Outcome<List<DNSResourceRecord>> current() {

        // if we read our local root hints file, and we can decode it, then we're good to go...
        Outcome<RootHintsSource> rfo = readFile();
        if( rfo.ok() ) {
            Outcome<List<DNSResourceRecord>> dfo = decode();
            if( dfo.ok() )
                return dfo;
            LOGGER.finest( "Problem decoding local root hints file: " + dfo.msg() );
        }
        LOGGER.finest( "Problem reading local root hints file: " + rfo.msg() );

        // something's wrong with our local root hints file - it's missing, bogus, or expired - so we'll have to read the URL...
        Outcome<RootHintsSource> ufo = readURL();
        if( ufo.ok() ) {
            Outcome<?> wfo = writeFile( ufo.info() );
            if( wfo.notOk() )
                LOGGER.log( Level.WARNING, wfo.msg(), wfo.cause() );
            Outcome<List<DNSResourceRecord>> dfo = decode();
            if( dfo.ok() )
                return dfo;
            LOGGER.finest( "Problem decoding downloaded root hints file: " + dfo.msg() );
        }
        LOGGER.finest( "Problem downloading root hints file: " + ufo.msg() );

        // if we get here, there's something seriously wrong - we have no valid root hints, so recursive resolution is going to fail...
        return rrlOutcome.notOk( "Cannot read valid root hints", new DNSResolverException( "Cannot read valid root hints", DNSResolverError.ROOT_HINTS_PROBLEMS ) );
    }


    /**
     * Simple record with just two fields:
     * <ul>
     *     <li>rootHints: a string containing the text of the root hints file</li>
     *     <li>downloadTimeMillis: the system time (in milliseconds) when we downloaded the root hints text</li>
     * </ul>
     */
    private record RootHintsSource( String rootHints, long downloadTimeMillis ){}
}
