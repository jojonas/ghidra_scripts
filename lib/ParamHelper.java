package lib;

import java.util.ArrayList;
import java.util.List;

import ghidra.app.emulator.EmulatorHelper;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.plugin.core.analysis.ConstantPropagationAnalyzer;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.FlowType;
import ghidra.program.util.SymbolicPropogator;
import ghidra.util.classfinder.ClassSearcher;
import ghidra.util.task.TaskMonitor;

public class ParamHelper {
    private Program program;
    private TaskMonitor monitor;

    public ParamHelper(Program program, TaskMonitor monitor) {
        this.program = program;
        this.monitor = monitor;
    }

    public long getParameterValue(Address call, Parameter param) throws Exception {
        return getParameterValues(call, param)[0];
    }

    public long[] getParameterValues(Address call, Function function) throws Exception {
        return getParameterValues(call, function.getParameters());
    }

    public long[] getParameterValues(Address call, Parameter... params) throws Exception {
        ArrayList<Parameter> registerParams = new ArrayList<Parameter>();
        ArrayList<Parameter> stackParams = new ArrayList<Parameter>();

        for (Parameter param : params) {
            if (param.isRegisterVariable()) {
                registerParams.add(param);
            } else if (param.isStackVariable()) {
                stackParams.add(param);
            }
        }

        ArrayList<Long> registerValues = getRegisterValues(call, registerParams);
        ArrayList<Long> stackValues = getStackValues(call, stackParams);

        long[] retval = new long[params.length];
        for (int i = 0; i < params.length; i++) {
            Parameter param = params[i];

            if (param.isRegisterVariable()) {
                retval[i] = registerValues.remove(0);
            } else if (param.isStackVariable()) {
                retval[i] = stackValues.remove(0);
            }
        }
        return retval;
    }

    private ArrayList<Long> getStackValues(Address call, List<Parameter> params) throws Exception {
        if (params.size() == 0) {
            return new ArrayList<Long>();
        }

        for (Parameter param : params) {
            if (!param.isStackVariable()) {
                throw new Exception("Parameter " + param.getOrdinal() + " is not a stack variable.");
            }
        }

        Instruction instruction = program.getListing().getInstructionAt(call);
        if (instruction == null) {
            return null;
        }

        Address init = call;
        Instruction curr = instruction.getPrevious();

        do {
            init = curr.getAddress();
            curr = curr.getPrevious();
        } while (curr != null && curr.getFlowType() != FlowType.FALL_THROUGH && !monitor.isCancelled());

        EmulatorHelper emulatorHelper = new EmulatorHelper(program);
        emulatorHelper.setBreakpoint(call);

        try {

            emulatorHelper.writeRegister(emulatorHelper.getPCRegister(), init.getOffset());

            long stackOffset = (call.getAddressSpace().getMaxAddress().getOffset() >> 1) - 0x7fff;
            emulatorHelper.writeRegister(emulatorHelper.getStackPointerRegister(), stackOffset);

            Address last = program.getListing().getInstructionAt(init).getPrevious().getAddress();
            while (!monitor.isCancelled()) {
                emulatorHelper.step(monitor);

                Address address = emulatorHelper.getExecutionAddress();
                CodeUnit current = program.getListing().getCodeUnitAt(address);

                if (address.equals(last)) {
                    // Skip bad instructions
                    Address gotoAddress = current.getMaxAddress().next();
                    emulatorHelper.writeRegister(emulatorHelper.getPCRegister(), gotoAddress.getOffset());
                    continue;
                } else {
                    last = address;
                }

                if (address.equals(call)) {
                    ArrayList<Long> values = new ArrayList<Long>();
                    for (Parameter param : params) {
                        int start = param.getStackOffset() - param.getLength();
                        long value = emulatorHelper.readStackValue(start, param.getLength(), true).longValue();

                        values.add(Long.valueOf(value));
                    }
                    return values;
                }

            }
        } finally {
            emulatorHelper.clearBreakpoint(call);
            emulatorHelper.dispose();
        }

        return null;
    }

    private ConstantPropagationAnalyzer getConstantAnalyzer() {
        AutoAnalysisManager mgr = AutoAnalysisManager.getAnalysisManager(program);
        List<ConstantPropagationAnalyzer> analyzers = ClassSearcher.getInstances(ConstantPropagationAnalyzer.class);
        for (ConstantPropagationAnalyzer analyzer : analyzers) {
            if (analyzer.canAnalyze(program)) {
                return (ConstantPropagationAnalyzer) mgr.getAnalyzer(analyzer.getName());
            }
        }
        return null;
    }

    private ArrayList<Long> getRegisterValues(Address call, ArrayList<Parameter> params) throws Exception {
        if (params.size() == 0) {
            return new ArrayList<Long>();
        }

        for (Parameter param : params) {
            if (!param.isRegisterVariable()) {
                throw new Exception("Parameter " + param.getOrdinal() + " is not a register variable.");
            }
        }

        Function caller = program.getListing().getFunctionContaining(call);

        ConstantPropagationAnalyzer analyzer = getConstantAnalyzer();
        SymbolicPropogator symEval = new SymbolicPropogator(program);
        symEval.setParamRefCheck(true);
        symEval.setReturnRefCheck(true);
        symEval.setStoredRefCheck(true);
        analyzer.flowConstants(program, caller.getEntryPoint(), caller.getBody(),
                symEval, monitor);

        ArrayList<Long> values = new ArrayList<Long>();
        for (Parameter param : params) {
            SymbolicPropogator.Value value = symEval.getRegisterValue(call, param.getRegister());
            values.add(Long.valueOf(value.getValue()));
        }
        return values;
    }
}
