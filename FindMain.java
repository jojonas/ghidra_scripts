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
import lib.ParamHelper;

public class FindMain extends GhidraScript {
    private static final DataType INT = IntegerDataType.dataType;
    private static final DataType CHAR_PTR = PointerDataType.getPointer(CharDataType.dataType, -1);
    private static final DataType CHAR_PTR_PTR = PointerDataType.getPointer(CHAR_PTR, -1);
    private static final DataType VOID_PTR = PointerDataType.getPointer(VoidDataType.dataType, -1);

    private FunctionManager fm;

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

    @Override
    public void run() throws Exception {
        fm = currentProgram.getFunctionManager();

        Function main = null;

        if (main == null) {
            Optional<Function> omain = StreamSupport.stream(
                    fm
                            .getFunctions(true)
                            .spliterator(),
                    false)
                    .filter(f -> f.getName().equals("main"))
                    .findFirst();

            if (omain.isPresent()) {
                if (askYesNo(FindMain.class.getName(),
                        "Existing main function detected at " + omain.get().getEntryPoint() + ". Use it?")) {
                    main = omain.get();
                }
            }
        }

        if (main == null) {
            main = detectMain();
        }

        if (main == null) {
            printerr("main function not found.");
            return;
        }

        if (main.isThunk()) {
            printerr("Main is a thunked function?");
        }

        setMainSignature(main);
        goTo(main);
    }

    private Function detectMain() throws Exception {
        Optional<Function> libcStartMain = StreamSupport.stream(
                fm
                        .getFunctions(true)
                        .spliterator(),
                false)
                .filter(f -> f.getName().equals("__libc_start_main"))
                .filter(f -> f.isThunk())
                .findFirst();

        if (!libcStartMain.isPresent()) {
            printerr("Could not find __libc_start_main!");
            return null;
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
            return null;
        }

        ParamHelper ph = new ParamHelper(currentProgram, monitor);
        long value = ph.getParameterValue(libcStartMainInvocationAddress.get(), libcStartMain.get().getParameter(0));
        if (value == 0) {
            return null;
        }

        Address mainAddress = toAddr(value);
        Function main = getOrCreateFunctionAt(mainAddress);

        return main;
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
