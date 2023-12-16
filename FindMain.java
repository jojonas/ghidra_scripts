// Find main() and fix its signature.
//@category Functions
//@author Jonas Lieb

import java.util.Optional;
import java.util.stream.StreamSupport;

import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.CharDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.data.ParameterDefinition;
import ghidra.program.model.data.ParameterDefinitionImpl;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.VoidDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.util.SymbolicPropogator;
import ghidra.util.exception.CancelledException;
import lib.ScriptUtils;

public class FindMain extends GhidraScript {
    private static final DataType INT = IntegerDataType.dataType;
    private static final DataType CHAR_PTR = PointerDataType.getPointer(CharDataType.dataType, -1);
    private static final DataType CHAR_PTR_PTR = PointerDataType.getPointer(CHAR_PTR, -1);
    private static final DataType VOID_PTR = PointerDataType.getPointer(VoidDataType.dataType, -1);

    private DataTypeManager dtm;

    private void setMainSignature(Function func) {
        ScriptUtils.setFunctionSignature(
                func,
                "main",
                new ParameterDefinition[] {
                        new ParameterDefinitionImpl("argc", INT, "Number of arguments"),
                        new ParameterDefinitionImpl("argv", CHAR_PTR_PTR, "Array of arguments"),
                },
                INT);
    }

    private void setLibcStartMainSignature(Function func) {
        ScriptUtils.setFunctionSignature(
                func,
                "__libc_start_main",
                new ParameterDefinition[] {
                        new ParameterDefinitionImpl("main", VOID_PTR, "Main function"),
                        new ParameterDefinitionImpl("argc", INT, "Number of arguments"),
                        new ParameterDefinitionImpl("argv", CHAR_PTR_PTR, "Array of arguments"),
                        new ParameterDefinitionImpl("init", VOID_PTR, "Initializer function"),
                        new ParameterDefinitionImpl("fini", VOID_PTR, "Exit handler function"),
                        new ParameterDefinitionImpl("rtld_fini", VOID_PTR, "Unload shared resources handler function"),
                        new ParameterDefinitionImpl("stack_end", VOID_PTR, null),
                },
                INT);
    }

    public long getParameterValue(Function func, Address address, int index) throws CancelledException {
        final Parameter parameter = func.getParameter(index);
        if (parameter == null) {
            printerr("Unable to retrieve parameter " + index);
            return 0;
        }
        if (!parameter.isRegisterVariable()) {
            printerr("Currently only processors passing parameters via registers are supported.");
            return 0;
        }

        Function caller = getFunctionContaining(address);
        if (caller == null) {
            printerr("Could not find function containing " + address);
            return 0;
        }

        SymbolicPropogator prop = ScriptUtils.analyzeFunction(caller, monitor);
        SymbolicPropogator.Value value = prop.getRegisterValue(address, parameter.getRegister());
        if (value == null) {
            printerr("Could not get register value for parameter " + index);
            return 0;
        }

        return value.getValue();
    }

    @Override
    public void run() throws Exception {
        dtm = currentProgram.getDataTypeManager();

        Optional<Function> libcStartMain = StreamSupport.stream(
                currentProgram.getFunctionManager()
                        .getFunctions(true)
                        .spliterator(),
                false)
                .filter(f -> f.getName().equals("__libc_start_main"))
                .filter(f -> f.isThunk())
                .findFirst();

        if (!libcStartMain.isPresent()) {
            printerr("Could not find __libc_start_main!");
            return;
        }

        setLibcStartMainSignature(libcStartMain.get());

        final ReferenceManager manager = currentProgram.getReferenceManager();
        Optional<Address> libcStartMainInvocationAddress = StreamSupport.stream(
                manager
                        .getReferencesTo(libcStartMain.get().getEntryPoint())
                        .spliterator(),
                false)
                .filter(r -> r.getReferenceType().isCall())
                .map(Reference::getFromAddress)
                .findFirst();

        if (!libcStartMainInvocationAddress.isPresent()) {
            printerr("Could not find invocation of __libc_start_main!");
            return;
        }

        long value = getParameterValue(libcStartMain.get(), libcStartMainInvocationAddress.get(), 0);
        if (value != 0) {
            Address mainAddress = toAddr(value);
            Function main = getOrCreateFunctionAt(mainAddress);
            if (main.isThunk()) {
                printerr("Main is a thunked function?");
            } else {
                setMainSignature(main);
                goTo(main);
            }
        }

        value = getParameterValue(libcStartMain.get(), libcStartMainInvocationAddress.get(), 3);
        if (value != 0) {
            Address initAddress = toAddr(value);
            Function init = getOrCreateFunctionAt(initAddress);
            ScriptUtils.setFunctionSignature(init, "init", null, null);
        }

        value = getParameterValue(libcStartMain.get(), libcStartMainInvocationAddress.get(), 4);
        if (value != 0) {
            Address finiAddress = toAddr(value);
            Function fini = getOrCreateFunctionAt(finiAddress);
            ScriptUtils.setFunctionSignature(fini, "fini", null, null);
        }

        /*
         * value = getParameterValue(libcStartMain.get(),
         * libcStartMainInvocationAddress.get(), 5);
         * if (value != 0) {
         * Address finiAddress = toAddr(value);
         * Function fini = getOrCreateFunctionAt(finiAddress);
         * ScriptUtils.setFunctionSignature(fini, "rtld_fini", null, null);
         * }
         */
    }

    private Function getOrCreateFunctionAt(Address address) {
        FunctionManager fm = currentProgram.getFunctionManager();
        Function func = fm.getFunctionAt(address);
        if (func == null) {
            CreateFunctionCmd cmd = new CreateFunctionCmd(address);
            if (!runCommand(cmd)) {
                printerr("Could not create main function at " + address);
                return null;
            }
            func = cmd.getFunction();
        }

        return func;
    }
}
