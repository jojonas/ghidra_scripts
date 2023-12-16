package lib;

import java.util.List;

import ghidra.app.cmd.function.ApplyFunctionSignatureCmd;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.plugin.core.analysis.ConstantPropagationAnalyzer;
import ghidra.program.model.data.Category;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.FunctionDefinitionDataType;
import ghidra.program.model.data.ParameterDefinition;
import ghidra.program.model.data.VoidDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionSignature;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.SymbolicPropogator;
import ghidra.util.classfinder.ClassSearcher;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public final class ScriptUtils {
    public static void setFunctionSignature(Function function, String name, ParameterDefinition[] params,
            DataType returnValue) {
        if (params == null) {
            params = new ParameterDefinition[] {};
        }

        if (returnValue == null) {
            returnValue = VoidDataType.dataType;
        }

        Program program = function.getProgram();

        Category rootCategory = program.getDataTypeManager().getRootCategory();
        CategoryPath categoryPath = rootCategory.getCategoryPath();

        FunctionDefinitionDataType functionDefinition = new FunctionDefinitionDataType(categoryPath, "main");
        functionDefinition.setReturnType(returnValue);

        functionDefinition.setArguments(params);

        FunctionSignature newSignature = functionDefinition;

        ApplyFunctionSignatureCmd cmd = new ApplyFunctionSignatureCmd(
                function.getEntryPoint(),
                newSignature,
                SourceType.USER_DEFINED);
        cmd.applyTo(program);
    }

    public static ConstantPropagationAnalyzer getConstantAnalyzer(Program program) {
        AutoAnalysisManager mgr = AutoAnalysisManager.getAnalysisManager(program);
        List<ConstantPropagationAnalyzer> analyzers = ClassSearcher.getInstances(ConstantPropagationAnalyzer.class);
        for (ConstantPropagationAnalyzer analyzer : analyzers) {
            if (analyzer.canAnalyze(program)) {
                return (ConstantPropagationAnalyzer) mgr.getAnalyzer(analyzer.getName());
            }
        }
        return null;
    }

    public static SymbolicPropogator analyzeFunction(Function function, TaskMonitor monitor)
            throws CancelledException {
        Program program = function.getProgram();
        ConstantPropagationAnalyzer analyzer = getConstantAnalyzer(program);
        SymbolicPropogator symEval = new SymbolicPropogator(program);
        symEval.setParamRefCheck(true);
        symEval.setReturnRefCheck(true);
        symEval.setStoredRefCheck(true);
        analyzer.flowConstants(program, function.getEntryPoint(), function.getBody(),
                symEval, monitor);
        return symEval;
    }
}
