# 第一次修改记录：尾调用、静态库模型与拷贝污点传播

日期：2026-10-28。基于上游提交 `658b41389b2fc16c2fcd4bfc5610f6c26d31ca6f`。

本次修改解决部分外部尾调用和间接跳转无法继续分析的问题，并修正 `memcpy` 模型的字节及污点传播。配合独立参考核验后的库函数名称，Windows x64 样例已经访问拷贝调用并执行到主函数返回。尚未确认样例中的预期缓冲区溢出。

## 修改范围

| 文件 | 修改 |
| --- | --- |
| `Config.java`、`ConfigDialog.java/.form` | 增加默认关闭的 `-modelStaticLibs` 和界面开关 |
| `FunctionModelManager.java` | 精确名称选择静态库模型，注册 `fputs` |
| `PcodeVisitor.java` | 外部/内部尾调用返回、BRANCHIND 绝对目标、直接及间接调用模型选择 |
| `CFG.java` | 动态发现目标时补齐函数内目标块后继 |
| `Context.java` | 检查取消中断，等待工作线程停止后再返回 |
| `FputsFunction.java` | 保留输入字符串、概括未知整数返回值 |
| `MemcpyFunction.java` | 按字节数复制零字节和 TOP 污点，多候选效果合并，修正 size_t 与目的指针返回 |
| `BinAbsInspector.java` | 提示仍无退出状态的上下文，避免把分析结束误认为完整覆盖 |
| `TailCallRegression.java` | 可用 Ghidra headless 运行的38项聚焦回归断言 |

生产代码没有样例地址硬编码。`EnterCriticalSection`、`LeaveCriticalSection` 只概括正常返回，不精确模拟锁状态或临界区对象的内部写入。未知 API 不自动当成无副作用函数。

内部尾调用复用调用求解和返回通知，但不再压入物理返回地址。目标函数返回后，包装函数只传播结果，避免重复弹栈。第一版尾调用识别限定 x64、栈已恢复、目标唯一且已识别为函数。

## 静态库模型的使用

```text
-postScript BinAbsInspector.java "@@-entry <entry-address> -disableZ3 -all -modelStaticLibs -timeout 120"
```

只有确认的全局库函数名称才应启用该选项。Function ID、BSim 和人工核对负责名称恢复；本补丁没有把 BSim 集成进求解器，也不会自动补全未知 API 的语义。

本次实验不读取目标源码或 PDB。独立参考 DLL 由本机预编译 CRT 库链接生成，函数名称来自参考 DLL 导出表。

- 外层输出包装函数没有直接 BSim 命中。其内部实现与独立参考的相似度为1.0、Confidence约90.73，再人工核对 stdout、参数列表、选项及辅助调用后恢复 `printf`。
- `memcpy` 与参考导出函数的相似度约0.9793、Confidence约577.26，复核参数和拷贝结构后恢复名称。
- 相似度与 Confidence 都不是正确率；没有把低区分度的最高候选自动改名。

## 实验结果及归因

环境：Windows x64、Ghidra 12.1.4、JDK21，禁用Z3，求解时间限制120秒。

| 阶段 | 主函数记录指令数 | 上下文数 | 拷贝/主函数RET | 超时 | 候选告警 |
| --- | ---: | ---: | --- | --- | ---: |
| 早期外部尾调用版本 | 80 | 324 | 均未到达 | 是 | 115 |
| 仅增加本轮间接跳转修复 | 80 | 316 | 均未到达 | 是 | 112 |
| 核验 printf 并使用现有模型 | 128 | 11 | 均到达 | 否 | 21 |
| 再恢复 memcpy 并使用修正模型 | 128 | 9 | 均到达 | 否 | 5 |

上下文包含调用历史，不是独立函数数量；超时阶段的覆盖会受调度影响。不能把最终进展全部归因于引擎补丁，实际突破还依赖正确应用输出模型。

最终在拷贝调用前观察到源缓冲区 `TOP#1`，调用后目的缓冲区出现同一污点标记。主函数生成非空退出状态。剩余5条告警为格式字符串候选，未确认为真实漏洞。

## 构建与回归

原有 Gradle 构建流程保留。另提供本机依赖构建脚本，已在 Ghidra12.1.4/JDK21 环境验证；它生成插件 JAR，不自动安装，也不是完整扩展 ZIP：

```powershell
./scripts/build-local.ps1 -GhidraInstallDir '<Ghidra目录>' -JavaHome '<JDK目录>' -DependencyDir '<已准备的依赖JAR目录>'
```

产物：`build/local/BinAbsInspector.jar`。完整扩展的打包及依赖部署仍按上游说明执行。该脚本不下载依赖，使用已安装的 Ghidra、仓库 `lib` 及可选的 `DependencyDir`。需按 `build.gradle` 预先准备 Jackson、error_prone_annotations、Commons Lang 等依赖；本次验证复用了本机现有依赖，没有将额外第三方 JAR 提交到仓库。

安装新 JAR 后重启 Ghidra，以使 headless 测试加载新类。在一个独立临时项目里导入任意合适的 x64 PE，禁用自动分析，再运行：

```text
analyzeHeadless <临时项目目录> regression -import <x64-PE路径> -readOnly -noanalysis -scriptPath <仓库>/src/test/resources/ghidra_scripts -postScript TailCallRegression.java <结果txt路径>
```

预期：结果文件末行 `TOTAL 38 passed`。脚本临时创建指令和外部引用，使用 `-readOnly` 丢弃修改；测试地址区间 `0x150000000..0x150000fff` 需未被输入PE占用。无需目标源码和PDB。

覆盖绝对间接跳转、新目标后继、内外部尾调用、普通CALL/CALLIND、No Return、IAT、歧义拒绝、栈平衡、调用者局部污点、memcpy零字节/TOP/多长度/零长度/返回值，以及取消与恢复。没有运行上游 Gradle 全套测试。

## 未解决的限制

- 目标实验中的未知字符串长度被原有 `strlen` 逻辑估成16，最终长度候选不符合真实输入上限；相关原生拷贝越界候选不能直接当作真实漏洞。
- 原有路径过滤与栈成员边界识别仍有限，尚未确认预期缓冲区溢出。
- 锁相关并发语义、未知 API、多目标内部尾调用、x86-32及其他架构不在本次已验证范围内。
- `memcpy` 模型只处理已有上限内的具体长度，未知长度或大于256字节时明确报告内存效果尚未概括。
- 不保证完整模拟 `FILE`、外部I/O、全部输入字节和终止符关系。

本记录确认的是控制流可继续及部分污点传播正确，不能据此声称工具已可靠检测真实程序中的全部漏洞。
