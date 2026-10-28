package com.bai.env.funcs.externalfuncs;


import com.bai.env.AbsEnv;
import com.bai.env.ALoc;
import com.bai.env.AbsVal;
import com.bai.env.Context;
import com.bai.env.KSet;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.UnsignedIntegerDataType;
import ghidra.program.model.data.UnsignedLongLongDataType;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.pcode.PcodeOp;
import com.bai.util.Logging;
import com.bai.util.StringUtils;
import com.bai.util.GlobalState;

import java.util.Set;


/**
 * void *memcpy(void *str1, const void *str2, size_t n)
 */
public class MemcpyFunction extends ExternalFunctionBase {

    private static final Set<String> staticSymbols = Set.of("memcpy");

    public MemcpyFunction() {
        super(staticSymbols);
        addDefaultParam("dest", PointerDataType.dataType);
        addDefaultParam("src", PointerDataType.dataType);
        addDefaultParam("n", IntegerDataType.dataType);
        setReturnType(PointerDataType.dataType);
    }

    @Override
    public void defineDefaultSignature(Function function) {
        super.defineDefaultSignature(function);
        int transaction = function.getProgram().startTransaction("define memcpy ABI");
        try {
            // n 是 size_t，宽度与目标指针一致；memcpy 返回目的地址。
            function.getParameter(2).setDataType(GlobalState.arch.getDefaultPointerSize() == 8
                ? UnsignedLongLongDataType.dataType : UnsignedIntegerDataType.dataType, SourceType.ANALYSIS);
            function.setReturnType(PointerDataType.dataType, SourceType.ANALYSIS);
        } catch (ghidra.util.exception.InvalidInputException e) {
            throw new IllegalStateException("Cannot define memcpy signature", e);
        } finally {
            function.getProgram().endTransaction(transaction, true);
        }
    }

    @Override
    public void invoke(PcodeOp pcode, AbsEnv inOutEnv, AbsEnv tmpEnv, Context context, Function calleeFunc) {
        KSet dstPtrKSet = getParamKSet(calleeFunc, 0, inOutEnv);
        KSet srcPtrKSet = getParamKSet(calleeFunc, 1, inOutEnv);
        KSet sizeKSet = getParamKSet(calleeFunc, 2, inOutEnv);
        if (!dstPtrKSet.isNormal() || !srcPtrKSet.isNormal() || !sizeKSet.isNormal()) {
            Logging.warn("Unresolved memcpy arguments: memory effect not summarized");
            return;
        }
        AbsEnv before = new AbsEnv(inOutEnv);
        AbsEnv result = null;
        for (AbsVal srcPtr : srcPtrKSet) {
            if (srcPtr.isBigVal()) continue;
            for (AbsVal dstPtr : dstPtrKSet) {
                if (dstPtr.isBigVal()) continue;
                for (AbsVal size : sizeKSet) {
                    if (!size.getRegion().isGlobal() || size.isBigVal() || size.getValue() < 0
                            || size.getValue() > StringUtils.MAX_LEN) {
                        Logging.warn("Unsupported memcpy size: memory effect not summarized");
                        return;
                    }
                    AbsEnv branch = new AbsEnv(before);
                    // 从调用前快照按字节复制，零字节和 TOP 污点均照常传播。
                    for (int offset = 0; offset < size.getValue(); offset++) {
                        ALoc source = ALoc.getALoc(srcPtr.getRegion(), srcPtr.getValue() + offset, 1);
                        KSet value = before.get(source);
                        if (value.isBot()) value = KSet.getTop(srcPtrKSet.getTaints());
                        ALoc destination = ALoc.getALoc(dstPtr.getRegion(), dstPtr.getValue() + offset, 1);
                        branch.set(destination, value, true);
                    }
                    ALoc returnValue = getReturnALoc(calleeFunc, false);
                    if (returnValue != null) branch.set(returnValue,
                        new KSet(returnValue.getLen() * 8, dstPtrKSet.getTaints()).insert(dstPtr), true);
                    // 每个长度对应独立效果，合并时保留短拷贝未覆盖的旧字节。
                    if (result == null) result = branch;
                    else {
                        AbsEnv joined = result.join(branch);
                        if (joined != null) result = joined;
                    }
                }
            }
        }
        if (result != null) {
            for (org.javimmutable.collections.JImmutableMap.Entry<ALoc, KSet> entry : result.getEnvMap()) {
                inOutEnv.set(entry.getKey(), entry.getValue(), true);
            }
        }
    }

}
