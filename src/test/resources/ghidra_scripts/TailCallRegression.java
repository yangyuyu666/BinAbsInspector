//@category Analysis
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.pcode.*;
import com.bai.env.*;
import com.bai.env.region.*;
import com.bai.solver.*;
import com.bai.env.funcs.FunctionModelManager;
import com.bai.util.*;
import java.nio.*;
import java.nio.file.*;
import java.lang.reflect.Method;

public class TailCallRegression extends GhidraScript {
    private Address base;
    private StringBuilder results = new StringBuilder();
    private int passed;

    private ALoc register(String name) {
        ghidra.program.model.lang.Register value = currentProgram.getRegister(name);
        return ALoc.getALoc(Reg.getInstance(), value.getOffset(), value.getMinimumByteSize());
    }

    private void check(boolean value, String name) {
        if (!value) throw new AssertionError(name);
        results.append("PASS ").append(name).append('\n');
        passed++;
    }

    private byte[] relative(int opcode, Address from, Address to) {
        return ByteBuffer.allocate(5).order(ByteOrder.LITTLE_ENDIAN).put((byte)opcode)
            .putInt((int)to.subtract(from.add(5))).array();
    }

    private Function fixture(int offset, byte[] bytes) throws Exception {
        Address address = base.add(offset);
        currentProgram.getMemory().setBytes(address, bytes);
        disassemble(address);
        return currentProgram.getFunctionManager().createFunction("tail_fixture_" + offset, address,
            new AddressSet(address, address.add(bytes.length - 1)), SourceType.USER_DEFINED);
    }

    private Function tail(int offset, String symbol, boolean noReturn) throws Exception {
        Address address = base.add(offset);
        Address slot = base.add(0xc00 + offset / 8);
        byte[] bytes = ByteBuffer.allocate(6).order(ByteOrder.LITTLE_ENDIAN)
            .put((byte)0xff).put((byte)0x25).putInt((int)slot.subtract(address.add(6))).array();
        Function function = fixture(offset, bytes);
        ExternalLocation external = currentProgram.getExternalManager().addExtFunction(
            "TailRegression", symbol, null, SourceType.USER_DEFINED);
        external.getFunction().setNoReturn(noReturn);
        currentProgram.getReferenceManager().addMemoryReference(address, slot, RefType.INDIRECTION,
            SourceType.USER_DEFINED, 0);
        currentProgram.getReferenceManager().addExternalReference(slot, 0, external,
            SourceType.USER_DEFINED, RefType.DATA);
        currentProgram.getReferenceManager().addExternalReference(address, 0, external,
            SourceType.USER_DEFINED, RefType.COMPUTED_JUMP);
        return function;
    }

    private boolean handle(Function function, AbsEnv environment) throws Exception {
        Context context = Context.getEntryContext(function);
        PcodeVisitor visitor = new PcodeVisitor(context);
        Method method = PcodeVisitor.class.getDeclaredMethod("tryHandleExternalTailCall",
            PcodeOp.class, AbsEnv.class, AbsEnv.class);
        method.setAccessible(true);
        for (PcodeOp op : getInstructionAt(function.getEntryPoint()).getPcode(true)) {
            if (op.getOpcode() == PcodeOp.BRANCHIND)
                return (Boolean)method.invoke(visitor, op, environment, new AbsEnv());
        }
        throw new AssertionError("Missing BRANCHIND");
    }

    private AbsEnv initial(Function function, int stackOffset) {
        AbsEnv environment = new AbsEnv();
        environment.set(ALoc.getSPALoc(), new KSet(64).insert(
            AbsVal.getPtr(Local.getLocal(function), Local.getLocal(function).getBase() + stackOffset)), true);
        return environment;
    }

    @Override public void run() throws Exception {
        GlobalState.config = Config.HeadlessParser.parseConfig("@@-disableZ3 -modelStaticLibs -timeout 5");
        Logging.init();
        GlobalState.currentProgram = currentProgram;
        GlobalState.flatAPI = this;
        GlobalState.arch = new Architecture(currentProgram);
        FunctionModelManager.initAll();
        GlobalState.reset();
        base = toAddr("150000000");
        currentProgram.getMemory().createInitializedBlock("tail_regression", base, 4096, (byte)0,
            monitor, false).setExecute(true);

        Function lock = tail(0x100, "EnterCriticalSection", false);
        AbsEnv environment = initial(lock, 0);
        ALoc marker = ALoc.getALoc(Global.getInstance(), base.add(0xf00).getOffset(), 4);
        environment.set(marker, KSet.getTop(1), true);
        check(handle(lock, environment), "resolve_IAT_with_uninitialized_slot");
        check(!Context.getEntryContext(lock).getExitValue().isEmpty(), "tail_produces_exit_state");
        check(new AbsEnv(Context.getEntryContext(lock).getExitValue()).get(marker).getTaints() == 1,
            "tail_preserves_memory_taint");

        GlobalState.reset();
        check(!handle(lock, initial(lock, -8)), "reject_unrestored_stack");
        check(Context.getEntryContext(lock).getExitValue().isEmpty(), "rejected_stack_has_no_exit");

        GlobalState.reset();
        Function unknown = tail(0x180, "UnknownWriteApi", false);
        check(!handle(unknown, initial(unknown, 0)), "unknown_API_not_pure_return");

        GlobalState.reset();
        Function noReturn = tail(0x200, "ExitProcess", true);
        check(handle(noReturn, initial(noReturn, 0)), "recognize_noreturn_tail");
        check(Context.getEntryContext(noReturn).getExitValue().isEmpty(), "noreturn_does_not_wake_caller");

        GlobalState.reset();
        Function modeled = tail(0x280, "puts", false);
        AbsEnv modeledEnv = initial(modeled, 0);
        check(handle(modeled, modeledEnv), "apply_registered_API_model");
        check(modeledEnv.get(register("EAX")).isTop(),
            "puts_model_changes_return_value");

        GlobalState.reset();
        // 真实 CALL→包装函数→尾调用，检查返回后是否执行调用者的 RET。
        byte[] call = new byte[6];
        System.arraycopy(relative(0xe8, base.add(0x300), lock.getEntryPoint()), 0, call, 0, 5);
        call[5] = (byte)0xc3;
        Function caller = fixture(0x300, call);
        Context entry = Context.getEntryContext(caller);
        AbsEnv input = new AbsEnv();
        input.set(marker, KSet.getTop(1), true);
        ALoc callerBuffer = ALoc.getALoc(Local.getLocal(caller), Local.getLocal(caller).getBase() - 16, 4);
        input.set(callerBuffer, KSet.getTop(4), true);
        entry.initContext(input, false);
        Context.mainLoop(entry);
        check(entry.getAbsEnvIn().containsKey(base.add(0x305)), "resume_original_caller_after_tail");
        check(entry.getValueBefore(base.add(0x305)).get(callerBuffer).getTaints() == 4,
            "caller_local_buffer_taint_survives_tail_return");
        check(!entry.getExitValue().isEmpty(), "caller_reaches_RETURN");
        check(new AbsEnv(entry.getExitValue()).get(marker).getTaints() == 1, "caller_keeps_input_taint");
        KSet finalStack = new AbsEnv(entry.getExitValue()).get(ALoc.getSPALoc());
        check(finalStack.isNormal() && finalStack.isSingleton()
            && finalStack.iterator().next().getOffset() == 8, "return_address_popped_once_per_function");

        GlobalState.reset();
        byte[] branch = {(byte)0xff, (byte)0xe0, (byte)0xc3, (byte)0xc3};
        Function jump = fixture(0x380, branch);
        currentProgram.getReferenceManager().addMemoryReference(jump.getEntryPoint(), base.add(0x382),
            RefType.COMPUTED_JUMP, SourceType.USER_DEFINED, 0);
        currentProgram.getReferenceManager().addMemoryReference(jump.getEntryPoint(), base.add(0x383),
            RefType.COMPUTED_JUMP, SourceType.USER_DEFINED, 0);
        AbsEnv jumpEnv = initial(jump, 0);
        jumpEnv.set(register("RAX"),
            new KSet(64).insert(new AbsVal(base.add(0x382).getOffset()))
                .insert(new AbsVal(base.add(0x383).getOffset())), true);
        check(!handle(jump, jumpEnv), "internal_switch_target_not_external_tail");
        check(Context.getEntryContext(jump).getExitValue().isEmpty(), "internal_jump_has_no_synthetic_exit");

        GlobalState.reset();
        Function compare = fixture(0x400, new byte[]{(byte)0xc3});
        compare.setName("strncmp", SourceType.USER_DEFINED);
        compare.setReturnType(ghidra.program.model.data.IntegerDataType.dataType, SourceType.USER_DEFINED);
        byte[] indirect = ByteBuffer.allocate(13).order(ByteOrder.LITTLE_ENDIAN)
            .put((byte)0x48).put((byte)0xb8).putLong(compare.getEntryPoint().getOffset())
            .put((byte)0xff).put((byte)0xd0).put((byte)0xc3).array();
        Function indirectCaller = fixture(0x440, indirect);
        Context indirectContext = Context.getEntryContext(indirectCaller);
        indirectContext.initContext(new AbsEnv(), false);
        Context.mainLoop(indirectContext);
        check(indirectContext.getAbsEnvIn().containsKey(base.add(0x44c)), "ordinary_CALLIND_still_resumes");
        check(!indirectContext.getExitValue().isEmpty(), "ordinary_CALLIND_reaches_RETURN");

        GlobalState.reset();
        Function ambiguous = tail(0x480, "EnterCriticalSection", false);
        ExternalLocation other = currentProgram.getExternalManager().addExtFunction(
            "TailRegression", "LeaveCriticalSection", null, SourceType.USER_DEFINED);
        currentProgram.getReferenceManager().addExternalReference(ambiguous.getEntryPoint(), -1, other,
            SourceType.USER_DEFINED, RefType.COMPUTED_JUMP);
        check(!handle(ambiguous, initial(ambiguous, 0)), "ambiguous_external_targets_not_merged_blindly");

        GlobalState.reset();
        Function output = tail(0x500, "fputs", false);
        AbsEnv outputEnv = initial(output, 0);
        outputEnv.set(marker, KSet.getTop(2), true);
        check(handle(output, outputEnv), "fputs_model_applied");
        check(outputEnv.get(marker).getTaints() == 2, "fputs_preserves_input_memory");

        GlobalState.reset();
        byte[] dynamic = new byte[22];
        java.util.Arrays.fill(dynamic, (byte)0x90);
        ByteBuffer.wrap(dynamic).order(ByteOrder.LITTLE_ENDIAN).put((byte)0x48).put((byte)0xb8)
            .putLong(base.add(0x610).getOffset()).put((byte)0xff).put((byte)0xe0);
        ByteBuffer.wrap(dynamic, 16, 6).order(ByteOrder.LITTLE_ENDIAN).put((byte)0xb8).putInt(42).put((byte)0xc3);
        Function dynamicFunction = fixture(0x600, dynamic);
        disassemble(base.add(0x610));
        Context dynamicContext = Context.getEntryContext(dynamicFunction);
        dynamicContext.initContext(new AbsEnv(), false);
        Context.mainLoop(dynamicContext);
        check(dynamicContext.getAbsEnvIn().containsKey(base.add(0x610)), "BRANCHIND_uses_absolute_address");
        check(dynamicContext.getAbsEnvIn().containsKey(base.add(0x615)), "dynamic_target_block_successors_added");
        check(new AbsEnv(dynamicContext.getExitValue()).get(register("EAX")).equals(new KSet(32).insert(new AbsVal(42))),
            "dynamic_target_executes_body_and_RETURN");

        GlobalState.reset();
        Function internalTarget = fixture(0x680, new byte[]{(byte)0xb8,42,0,0,0,(byte)0xc3});
        Function internalWrapper = fixture(0x700, new byte[]{(byte)0xff,(byte)0xe0});
        byte[] dispatch = new byte[16];
        ByteBuffer.wrap(dispatch).order(ByteOrder.LITTLE_ENDIAN).put((byte)0x48).put((byte)0xb8)
            .putLong(internalTarget.getEntryPoint().getOffset());
        System.arraycopy(relative(0xe8, base.add(0x78a), internalWrapper.getEntryPoint()), 0, dispatch, 10, 5);
        dispatch[15] = (byte)0xc3;
        Function dispatchCaller = fixture(0x780, dispatch);
        Context dispatchContext = Context.getEntryContext(dispatchCaller);
        AbsEnv dispatchInput = new AbsEnv();
        dispatchInput.set(marker, KSet.getTop(8), true);
        dispatchContext.initContext(dispatchInput, false);
        Context.mainLoop(dispatchContext);
        check(dispatchContext.getAbsEnvIn().containsKey(base.add(0x78f)), "internal_tail_resumes_original_caller");
        check(new AbsEnv(dispatchContext.getExitValue()).get(register("EAX")).equals(new KSet(32).insert(new AbsVal(42))),
            "internal_tail_propagates_real_target_result");
        check(new AbsEnv(dispatchContext.getExitValue()).get(marker).getTaints() == 8,
            "internal_tail_preserves_memory_taint");
        KSet dispatchStack = new AbsEnv(dispatchContext.getExitValue()).get(ALoc.getSPALoc());
        check(dispatchStack.isNormal() && dispatchStack.isSingleton()
            && dispatchStack.iterator().next().getOffset() == 8, "internal_tail_does_not_double_pop_return_address");

        GlobalState.reset();
        Function memoryCopy = tail(0xa00, "memcpy", false);
        AbsEnv copyEnv = initial(memoryCopy, 0);
        long sourceAddress = base.add(0xf20).getOffset();
        long destinationAddress = base.add(0xf40).getOffset();
        ALoc sourceBytes = ALoc.getALoc(Global.getInstance(), sourceAddress, 3);
        ALoc destinationBytes = ALoc.getALoc(Global.getInstance(), destinationAddress, 4);
        copyEnv.set(register("RCX"), new KSet(64).insert(new AbsVal(destinationAddress)), true);
        copyEnv.set(register("RDX"), new KSet(64).insert(new AbsVal(sourceAddress)), true);
        copyEnv.set(register("R8"), new KSet(64).insert(new AbsVal(3)), true);
        copyEnv.set(sourceBytes, new KSet(24).insert(new AbsVal(0x420041)), true);
        copyEnv.set(destinationBytes, new KSet(32).insert(new AbsVal(0x77777777)), true);
        check(handle(memoryCopy, copyEnv), "memcpy_model_applied");
        check(copyEnv.get(ALoc.getALoc(Global.getInstance(), destinationAddress + 2, 1))
            .equals(new KSet(8).insert(new AbsVal(0x42))), "memcpy_copies_past_embedded_NUL");
        check(copyEnv.get(ALoc.getALoc(Global.getInstance(), destinationAddress + 3, 1))
            .equals(new KSet(8).insert(new AbsVal(0x77))), "memcpy_does_not_write_beyond_count");
        check(copyEnv.get(register("RAX")).equals(new KSet(64).insert(new AbsVal(destinationAddress))),
            "memcpy_returns_destination_pointer");

        GlobalState.reset();
        AbsEnv taintedCopy = initial(memoryCopy, 0);
        taintedCopy.set(register("RCX"), new KSet(64).insert(new AbsVal(destinationAddress)), true);
        taintedCopy.set(register("RDX"), new KSet(64).insert(new AbsVal(sourceAddress)), true);
        taintedCopy.set(register("R8"), new KSet(64).insert(new AbsVal(3)), true);
        taintedCopy.set(sourceBytes, KSet.getTop(32), true);
        handle(memoryCopy, taintedCopy);
        check(taintedCopy.get(ALoc.getALoc(Global.getInstance(), destinationAddress, 1)).getTaints() == 32,
            "memcpy_propagates_TOP_memory_taint");

        GlobalState.reset();
        AbsEnv choiceCopy = initial(memoryCopy, 0);
        choiceCopy.set(register("RCX"), new KSet(64).insert(new AbsVal(destinationAddress)), true);
        choiceCopy.set(register("RDX"), new KSet(64).insert(new AbsVal(sourceAddress)), true);
        choiceCopy.set(register("R8"), new KSet(64).insert(new AbsVal(1)).insert(new AbsVal(3)), true);
        choiceCopy.set(sourceBytes, new KSet(24).insert(new AbsVal(0x420041)), true);
        choiceCopy.set(destinationBytes, new KSet(32).insert(new AbsVal(0x77777777)), true);
        handle(memoryCopy, choiceCopy);
        check(choiceCopy.get(ALoc.getALoc(Global.getInstance(), destinationAddress + 2, 1))
            .equals(new KSet(8).insert(new AbsVal(0x42)).insert(new AbsVal(0x77))),
            "memcpy_multiple_lengths_keep_unwritten_alternative");

        GlobalState.reset();
        AbsEnv zeroCopy = initial(memoryCopy, 0);
        zeroCopy.set(register("RCX"), new KSet(64).insert(new AbsVal(destinationAddress)), true);
        zeroCopy.set(register("RDX"), new KSet(64).insert(new AbsVal(sourceAddress)), true);
        zeroCopy.set(register("R8"), new KSet(64).insert(new AbsVal(0)), true);
        zeroCopy.set(destinationBytes, new KSet(32).insert(new AbsVal(0x77777777)), true);
        handle(memoryCopy, zeroCopy);
        check(zeroCopy.get(destinationBytes).equals(new KSet(32).insert(new AbsVal(0x77777777))),
            "memcpy_zero_length_keeps_destination");

        GlobalState.reset();
        Function cancelled = fixture(0xb00, new byte[]{(byte)0xc3});
        Context cancelledContext = Context.getEntryContext(cancelled);
        cancelledContext.initContext(new AbsEnv(), false);
        Thread.currentThread().interrupt();
        try { Context.mainLoop(cancelledContext); }
        finally { Thread.interrupted(); }
        check(cancelledContext.getExitValue().isEmpty(), "interrupted_worker_stops_before_execution");
        Context.mainLoop(cancelledContext);
        check(!cancelledContext.getExitValue().isEmpty(), "cancelled_worklist_remains_available_for_resume");

        results.append("TOTAL ").append(passed).append(" passed\n");
        Files.writeString(Path.of(getScriptArgs()[0]), results);
        println(results.toString());
        GlobalState.reset();
    }
}
