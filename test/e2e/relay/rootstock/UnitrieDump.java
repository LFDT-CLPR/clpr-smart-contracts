import org.rocksdb.Options;
import org.rocksdb.RocksDB;
import org.rocksdb.RocksIterator;

import java.io.PrintWriter;
import java.util.HexFormat;

/**
 * Dumps an RSKj Unitrie RocksDB store (`<database.dir>/unitrie`) as "keyHex valueHex" lines.
 * RSKj stores every non-embedded node under keccak256(message) and every long value under
 * keccak256(value), so the dump is a content-addressed node map the relayer walks to build
 * Unitrie proofs (RSKj 9.x has no eth_getProof).
 *
 * Run (the node must be stopped; RocksDB is opened read-only):
 *   java -cp rskj-core-<ver>-all.jar UnitrieDump.java <database.dir>/unitrie out.txt
 */
public class UnitrieDump {
    public static void main(String[] args) throws Exception {
        RocksDB.loadLibrary();
        HexFormat hex = HexFormat.of();
        long n = 0;
        try (Options o = new Options();
             RocksDB db = RocksDB.openReadOnly(o, args[0]);
             RocksIterator it = db.newIterator();
             PrintWriter w = new PrintWriter(args[1])) {
            for (it.seekToFirst(); it.isValid(); it.next()) {
                w.println(hex.formatHex(it.key()) + " " + hex.formatHex(it.value()));
                n++;
            }
        }
        System.out.println("dumped " + n + " entries");
    }
}
