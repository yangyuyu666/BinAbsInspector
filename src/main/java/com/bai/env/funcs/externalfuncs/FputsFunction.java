package com.bai.env.funcs.externalfuncs;

import com.bai.env.ALoc;
import com.bai.env.AbsEnv;
import com.bai.env.Context;
import com.bai.env.KSet;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.pcode.PcodeOp;
import java.util.Set;

public class FputsFunction extends ExternalFunctionBase {
    public FputsFunction() {
        super(Set.of("fputs"));
        addDefaultParam("str", PointerDataType.dataType);
        addDefaultParam("stream", PointerDataType.dataType);
        setReturnType(IntegerDataType.dataType);
    }

    @Override
    public void invoke(PcodeOp pcode, AbsEnv environment, AbsEnv temporary, Context context, Function function) {
        // 输出不改写输入字符串；返回值可能表示成功或失败，记为未知整数。
        ALoc result = getReturnALoc(function, false);
        if (result != null) environment.set(result, KSet.getTop(), true);
    }
}
