import org.apache.kafka.common.record.internal.MemoryRecords;
import org.apache.kafka.common.record.internal.MutableRecordBatch;
import org.apache.kafka.common.record.internal.Record;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.Paths;

/**
 * Kafka RecordBatch parsing harness — the "target binary" for vuln-pipeline.
 *
 * Reads a file's bytes and feeds them to Kafka's message-record parser
 * (MemoryRecords.readableRecords -> batch iteration), the most input-driven
 * memory path in the client library. A malformed RecordBatch (bad size fields,
 * bogus varints, huge lengths, invalid magic) exercises DefaultRecordBatch /
 * ByteUtils / MemoryRecordsBuilder and can surface Java memory errors.
 *
 * The JVM is launched (see run_harness.sh) with:
 *   -Xmx512m -XX:MaxDirectMemorySize=256m      # tight heap => OOM reachable
 *   -XX:+ExitOnOutOfMemoryError                 # OOM -> non-zero exit = "crash"
 *   -XX:+HeapDumpOnOutOfMemoryError             # forensics artifact
 *   -ea                                         # assertions enabled
 *
 * Agents may copy this file and compile their own variants (javac) to target
 * other entry points (ByteBufferAccessor + Message.read, Type decoding, etc.).
 */
public class Harness {
    public static void main(String[] args) throws Exception {
        if (args.length < 1) {
            System.out.println("usage: Harness <input-file>");
            return;
        }
        byte[] data = Files.readAllBytes(Paths.get(args[0]));
        ByteBuffer buf = ByteBuffer.wrap(data);
        MemoryRecords records = MemoryRecords.readableRecords(buf);
        int n = 0;
        for (MutableRecordBatch batch : records.batches()) {
            n++;
            for (Record r : batch) {
                r.toString(); // force key/value/headers access
            }
        }
        System.out.println("parsed batches: " + n + " ok");
    }
}
