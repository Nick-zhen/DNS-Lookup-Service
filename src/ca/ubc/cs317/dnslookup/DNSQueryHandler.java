package ca.ubc.cs317.dnslookup;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.SocketException;
import java.nio.ByteBuffer;
import java.util.Collections;
import java.util.HashSet;
import java.util.Random;
import java.util.Set;

public class DNSQueryHandler {

    private static final int DEFAULT_DNS_PORT = 53;
    private static DatagramSocket socket;
    private static boolean verboseTracing = false;
    private static int decodeOffset;

    private static final Random random = new Random();

    /**
     * Sets up the socket and set the timeout to 5 seconds
     *
     * @throws SocketException if the socket could not be opened, or if there was an
     *                         error with the underlying protocol
     */
    public static void openSocket() throws SocketException {
        socket = new DatagramSocket();
        socket.setSoTimeout(5000);
    }

    /**
     * Closes the socket
     */
    public static void closeSocket() {
        socket.close();
    }

    /**
     * Set verboseTracing to tracing
     */
    public static void setVerboseTracing(boolean tracing) {
        verboseTracing = tracing;
    }

    /**
     * Builds the query, sends it to the server, and returns the response.
     *
     * @param message Byte array used to store the query to DNS servers.
     * @param server  The IP address of the server to which the query is being sent.
     * @param node    Host and record type to be used for search.
     * @return A DNSServerResponse Object containing the response buffer and the transaction ID.
     * @throws IOException if an IO Exception occurs
     */
    public static DNSServerResponse buildAndSendQuery(byte[] message, InetAddress server,
                                                      DNSNode node) throws IOException {
        // build query or message
        int offset = 0;

        // create random Identification and assign it to message
        int identification = random.nextInt(65535);
        message[offset++] = (byte) (identification >>> 8);
        message[offset++] = (byte) (identification);
        // System.out.println(message[0]);
        // System.out.println(message[1]);

        // build flags(iterative queries)
        // QR, Opcode, AA, TC, RD, RA, Z, RCODE
        message[offset++] = 0x00;
        message[offset++] = 0x00;

        // QDCOUNT: 1
        message[offset++] = 0x00;
        message[offset++] = 0x01;

        // ANCOUNT: leave for RR
        message[offset++] = 0x00;
        message[offset++] = 0x00;
        // NSCOUNT
        message[offset++] = 0x00;
        message[offset++] = 0x00;
        // ARCOUNT
        message[offset++] = 0x00;
        message[offset++] = 0x00;

        // questions: QNAME, QTYPE, QCLASS
        // QNAME
        String[] splittedByDot = node.getHostName().split("\\."); // Dot is meta Charactor, we need \\
        for (int i = 0; i < splittedByDot.length; ++i) {
            message[offset++] = (byte) splittedByDot[i].length();
            for (int j = 0; j < splittedByDot[i].length(); ++j) {
                message[offset++] = (byte) splittedByDot[i].charAt(j);
            }
        }
        message[offset++] = 0x00; // ending of QNAME
        // QTYPE
        int type = node.getType().getCode();
        message[offset++] = (byte) ((type & 0x0000ff00) >>> 8);
        message[offset++] = (byte) (type & 0x000000ff);
        // QCLASS: Internet
        message[offset++] = 0x00;
        message[offset++] = 0x01;


        // create receive datagramPacket and receive
        byte[] buf = new byte[1024];
        DatagramPacket receivedPacket = new DatagramPacket(buf, buf.length);

        // try 3 times
        int triedTimes = 0;
        while (triedTimes < 3) {
            try {
                if (verboseTracing) {
                    System.out.println("");
                    System.out.println("");
                    System.out.println("QueryID     " + identification + " " + node.getHostName() + "  " + node.getType() + " --> " + server.getHostAddress());
                }
                // send query or message
                DatagramPacket datagramPacket = new DatagramPacket(message, offset, server, DEFAULT_DNS_PORT);
                socket.send(datagramPacket);

                // receive response
                socket.receive(receivedPacket);

                byte[] receivedData = receivedPacket.getData();

                // for testing
                // char[] HEX_ARRAY = "0123456789ABCDEF".toCharArray();
                // char[] hexChars = new char[receivedData.length * 2];
                // for (int j = 0; j < receivedData.length; j++) {
                //     int v = receivedData[j] & 0xFF;
                //     hexChars[j * 2] = HEX_ARRAY[v >>> 4];
                //     hexChars[j * 2 + 1] = HEX_ARRAY[v & 0x0F];
                // }
                // System.out.println(new String(hexChars));

                if (receivedData[0] == message[0] && receivedData[1] == message[1]) {
                    return new DNSServerResponse(ByteBuffer.wrap(receivedData), identification);
                }
            } catch (SocketException e) {
                triedTimes++;
            }
        }




        return null;
    }

    /**
     * Decodes the DNS server response and caches it.
     *
     * @param transactionID  Transaction ID of the current communication with the DNS server
     * @param responseBuffer DNS server's response
     * @param cache          To store the decoded server's response
     * @return A set of resource records corresponding to the name servers of the response.
     */
    public static Set<ResourceRecord> decodeAndCacheResponse(int transactionID, ByteBuffer responseBuffer,
                                                             DNSCache cache) {
        Set<ResourceRecord> rrs = new HashSet<>();

        // byte[] receivedData = responseBuffer.array();
        // char[] HEX_ARRAY = "0123456789ABCDEF".toCharArray();
        // char[] hexChars = new char[receivedData.length * 2];
        // for (int j = 0; j < receivedData.length; j++) {
        //     int v = receivedData[j] & 0xFF;
        //     hexChars[j * 2] = HEX_ARRAY[v >>> 4];
        //     hexChars[j * 2 + 1] = HEX_ARRAY[v & 0x0F];
        // }
        // System.out.println(new String(hexChars));


        int id = responseBuffer.getShort(0) & 0xffff;



        Byte headerFlag = responseBuffer.get(2);

        int AA = (headerFlag & 0x04) >>> 2; //header AA

        if(verboseTracing){
            System.out.println("ResponseID: " + id + " " + "Authoritative = " + String.valueOf(AA == 1));
        }
        int tc = headerFlag & 0b00000010 >>1; // tc=0 is not truncated
        int qr = (headerFlag & 0b10000000) >>> 7; // qr=1 is response
        // System.out.println("tc " + tc);
        // System.out.println("qr " + qr);
        // System.out.println("transactionID " + transactionID);
        // System.out.println("ID " + id);

        if(tc == 1 || qr == 0 || id != transactionID) return null;

        // AA will be used in the part2
        // int AA = (headerFlag & 0x04) >>> 2;

        // check RCODE
        int secondHalfFlag = responseBuffer.get(3);
        int RCODE = secondHalfFlag & 0x07;
        // System.out.println("RCODE " + RCODE);
        if (RCODE != 0x00 && !(AA == 1 && RCODE == 0x03)) {
            return Collections.emptySet();
        }

        int numOfAnswer = responseBuffer.getShort(6);
        int numOfAuthority = responseBuffer.getShort(8);
        int numOfAdditional = responseBuffer.getShort(10);
        // System.out.println("numOfAnswer " + numOfAnswer);
        // System.out.println("numOfAuthority " + numOfAuthority);
        // System.out.println("numOfAdditional " + numOfAdditional);

        //decode question


        decodeOffset = 12;
        // piazza mentioned we only have one question
        decodeOffset = Integer.valueOf(decompressStrings(decodeOffset, responseBuffer)[1]);
        // Qtype and Qclass
        decodeOffset += 4;

        // decode answers
        if(verboseTracing){
            System.out.println("  Answers " + "(" + numOfAnswer +")");
        }
        for( int i = 0; i < numOfAnswer; i++){
            decodeResourceRecord(responseBuffer, cache);
        }

        // decode Authority
        if(verboseTracing){
            System.out.println("  NameServers " + "(" + numOfAuthority +")");
        }
        for (int i = 0; i < numOfAuthority; ++i) {
            rrs.add(decodeResourceRecord(responseBuffer, cache));
        }
        // decode Additional information
        if(verboseTracing){
            System.out.println("  Additional Information " + "(" + numOfAdditional +")");
        }
        for (int i = 0; i < numOfAdditional; ++i) {
            decodeResourceRecord(responseBuffer, cache);
        }
        return rrs;
    }

    /**
     * Formats and prints record details (for when trace is on)
     *
     * @param record The record to be printed
     * @param rtype  The type of the record to be printed
     */
    private static void verbosePrintResourceRecord(ResourceRecord record, int rtype) {
        if (verboseTracing)
            System.out.format("       %-30s %-10d %-4s %s\n", record.getHostName(),
                    record.getTTL(),
                    record.getType() == RecordType.OTHER ? rtype : record.getType(),
                    record.getTextResult());
    }

    public static ResourceRecord decodeResourceRecord(ByteBuffer responseBuffer, DNSCache cache) {
        //
        //get  hostname
        String[] hostnameArr = decompressStrings(decodeOffset, responseBuffer);
        decodeOffset = Integer.valueOf(hostnameArr[1]);
        // System.out.println("decodeOffset " + decodeOffset);

        // need to check SOA and other type
        String hostname = hostnameArr[0].isEmpty() ? "" : hostnameArr[0].substring(0, hostnameArr[0].length() - 1);
        // get type
        int typeCode = responseBuffer.getShort(decodeOffset);
        RecordType type = RecordType.getByCode(typeCode);
        // skip Class right now.
        decodeOffset += 4;
        // get ttl
        long ttl = (long) responseBuffer.getInt(decodeOffset);
        decodeOffset += 4;

        // get RDlength
        int RDLEN = responseBuffer.getShort(decodeOffset) & 0xffff;
        decodeOffset += 2;


        // System.out.println("hostname " + hostname);
        // System.out.println("typeCode " + typeCode);
        // System.out.println("RDLEN " + RDLEN);

        //get result
        String result = "";
        ResourceRecord record = null;
        if(type == RecordType.A){
            int r1 = responseBuffer.get(decodeOffset++) & 0xff;
            int r2 = responseBuffer.get(decodeOffset++) & 0xff;
            int r3 = responseBuffer.get(decodeOffset++) & 0xff;
            int r4 = responseBuffer.get(decodeOffset++) & 0xff;

            result = r1+"."+ r2 + "." + r3+ "." + r4;

            // rr = new ResourceRecord(hostname, type, ttl, result);
            // verbosePrintResourceRecord(rr, type.getCode());
        } else if(type == RecordType.CNAME || type == RecordType.NS){
            int size = 0;
            while (size < RDLEN) {
                String[] readRes = decompressStrings(decodeOffset, responseBuffer);
                String currName = readRes[0];
                size += Integer.valueOf(readRes[1]) - decodeOffset;
                decodeOffset = Integer.valueOf(readRes[1]);
                result += currName;
            }
            result = result.substring(0, result.length() - 1);
        } else if (type == RecordType.AAAA){ // ipv6
            for (int i = 0; i < 16; i+=2) {
                result += Integer.toHexString(responseBuffer.getShort(decodeOffset) & 0xffff); // avoid negative short cast to int
                result += ":";
                decodeOffset += 2;
            }

            result = result.substring(0, result.length() - 1);
            // rr = new ResourceRecord(hostname, type, ttl, result);
            // verbosePrintResourceRecord(rr, type.getCode());
        } else if (type == RecordType.MX) {
            decodeOffset += RDLEN;
            result = "----";
        } else if (type == RecordType.SOA) {
            decodeOffset += RDLEN;
            result = "----";
        } else {
            decodeOffset += RDLEN;
            result = "----";
        }
        record = new ResourceRecord(hostname.toString(), type, ttl, result); // first constructor
        verbosePrintResourceRecord(record, type.getCode());
        cache.addResult(record);
        return record;
        // getByName()
        // InetAddress.getByAddress().
    }

    public static String[] decompressStrings(int offset, ByteBuffer responseBuffer) {
        String name = "";
        try {

            byte firstByte = responseBuffer.get(offset);
            if (firstByte == 0) { // reach the end
                offset++;
                String[] res = new String[] {name, String.valueOf(offset)};
                return res;
            } else if ((firstByte & 0xc0) == 0xc0) { // the case for pointer

                int startOffset = (int) (responseBuffer.getShort(offset) & 0x3fff);
                offset += 2;
                name = decompressStrings(startOffset, responseBuffer)[0];
            } else { // case for not pointer
                int len = (int) responseBuffer.get(offset);
                offset++;
                for (int i = 0; i < len; ++i) {
                    name += (char) responseBuffer.get(offset++);
                }
                name += ".";
                String[] ret = decompressStrings(offset, responseBuffer);
                name += ret[0];
                offset = Integer.valueOf(ret[1]);
            }
            return new String[] {name, String.valueOf(offset)};
        } catch (IndexOutOfBoundsException e) {
            offset++;
            String[] res = new String[] {name, String.valueOf(offset)};
            return res;
        }
    }

    // public static String readName(int offset, ByteBuffer responseBuffer) throws IndexOutOfBoundsException {
    //     String res = "";
    //     int len;
    //     while (responseBuffer.get(offset) != 0x00) {
    //         len = (int) responseBuffer.get(offset);
    //         offset++;
    //         for (int i = 0; i < len; ++i) {
    //             res += (char) responseBuffer.get(offset++);
    //         }
    //         res += ".";
    //     }
    //     return res.substring(0, res.length() - 1);
    // }
}
