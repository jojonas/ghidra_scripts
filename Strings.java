// Equivalent of "strings" command for Ghidra.
//@category Strings
//@author Jonas Lieb

import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.DataUtilities;
import ghidra.program.model.data.DataUtilities.ClearDataMode;
import ghidra.program.model.data.StringDataType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.util.task.TaskMonitor;

public class Strings extends GhidraScript {
    private static final int MIN_LENGTH = 4;

    @Override
    protected void run() throws Exception {
        TaskMonitor monitor = getMonitor();

        for (Data data : currentProgram.getListing().getData(true)) {
            if (monitor.isCancelled())
                break;

            if (data.isDefined()) {
                continue;
            }

            int length = getStringLength(data);
            if (length >= MIN_LENGTH) {
                println("Potential string at " + data.getAddress());

                DataUtilities.createData(
                        currentProgram,
                        data.getAddress(),
                        StringDataType.dataType,
                        -1,
                        false,
                        ClearDataMode.CLEAR_ALL_UNDEFINED_CONFLICT_DATA);
            }
        }
    }

    private int getStringLength(Data data) {
        for (int i = 0; i < Integer.MAX_VALUE; i++) {
            byte b = 0;

            try {
                b = data.getByte(i);
            } catch (MemoryAccessException e) {
                return -1;
            }

            if (!isPrintable(b)) {
                if (b == 0) {
                    return i;
                }

                return -1;
            }
        }

        return -1;
    }

    private static boolean isPrintable(byte b) {
        return b >= 0x20 && b <= 0x7E;
    }
}
