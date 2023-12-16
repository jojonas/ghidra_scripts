// Find interesting functions that are often associated with vulnerabilities.
//@category Functions
//@author Jonas Lieb

import java.awt.Color;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;

public class InterestingFunctions extends GhidraScript {
    enum Rating {
        DANGEROUS,
        WARNING,
        INFO,
        NONE,
    };

    public static final String[] DANGEROUS_FUNCTIONS = new String[] {
            // unbounded memory functions (dangerous)
            "strcpy",
            "wcscpy",
            "strcat",
            "wcscat",
            "sprintf",
            "vsprintf",
            "strtok",
            "gets",
            "fgets",
            "atoi",
            "atol",
    };

    public static final String[] WARNING_FUNCTIONS = new String[] {
            "strncpy",
            "strncat",
            "snprintf",
            "vsnprintf",
            "scanf",
            "sscanf",
            "vscanf",
            "vsscanf",
            "fscanf",
            "strlen",
            "wcslen",
    };

    public static final String[] INFO_FUNCTIONS = new String[] {
            // input functions
            "read",
            "fread",
            "getenv",

            // functions that execute commands
            "system",
            "popen",
            "exec",
            "execl",
            "execlp",
            "execle",
            "execv",
            "execvp",
            "execvpe",
            "execve",
            "exect",
            "execveat",

            // others
            "malloc"
    };

    @Override
    protected void run() throws Exception {
        FunctionManager fm = currentProgram.getFunctionManager();
        ReferenceManager rm = currentProgram.getReferenceManager();

        AddressSet invocations = new AddressSet();

        for (Function function : fm.getFunctions(true)) {
            Rating rating = rate(function);

            if (rating == Rating.NONE) {
                continue;
            }

            for (Reference reference : rm.getReferencesTo(function.getEntryPoint())) {
                if (!reference.getReferenceType().isCall()) {
                    continue;
                }

                Address address = reference.getFromAddress();
                Function caller = fm.getFunctionContaining(address);

                if (caller.isThunk()) {
                    continue;
                }

                println("At " + address + " : call to " + function.getName());

                invocations.add(address);

                Color color = getColor(rating);
                if (color != null) {
                    setBackgroundColor(address, color);
                }
            }
        }

        show("Interesting Function Calls", invocations);
    }

    private static boolean contains(String[] array, String needle) {
        for (String value : array) {
            if (value.equals(needle)) {
                return true;
            }
        }

        return false;
    }

    private static Rating rate(Function func) {
        String name = func.getName();

        if (contains(DANGEROUS_FUNCTIONS, name)) {
            return Rating.DANGEROUS;
        }

        if (contains(WARNING_FUNCTIONS, name)) {
            return Rating.WARNING;
        }

        if (contains(INFO_FUNCTIONS, name)) {
            return Rating.INFO;
        }

        return Rating.NONE;
    }

    private static Color getColor(Rating rating) {
        switch (rating) {
            case DANGEROUS:
                return new Color(255, 150, 105);
            case WARNING:
                return new Color(255, 230, 106);
            case INFO:
                return new Color(170, 250, 110);
            case NONE:
                return null;
        }

        return null;
    }
}
