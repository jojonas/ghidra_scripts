package lib;

import ghidra.app.cmd.function.ApplyFunctionSignatureCmd;
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
}
