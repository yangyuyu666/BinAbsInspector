param(
    [string]$GhidraInstallDir = $env:GHIDRA_INSTALL_DIR,
    [string]$JavaHome = $env:JAVA_HOME,
    [string]$DependencyDir
)

$ErrorActionPreference = 'Stop'
if (-not $GhidraInstallDir -or -not $JavaHome) {
    throw 'Specify -GhidraInstallDir and -JavaHome, or set GHIDRA_INSTALL_DIR and JAVA_HOME.'
}
$repoRoot = Split-Path -Parent $PSScriptRoot
$ghidraRoot = (Resolve-Path -LiteralPath $GhidraInstallDir).Path
$javaRoot = (Resolve-Path -LiteralPath $JavaHome).Path
$buildRoot = Join-Path $repoRoot 'build/local'
$classes = Join-Path $buildRoot 'classes'
New-Item -ItemType Directory -Force $classes | Out-Null

# 从已安装的 Ghidra 和仓库 lib 目录收集编译依赖，排除旧版插件自身。
$jars = @(Get-ChildItem (Join-Path $ghidraRoot 'Ghidra') -Recurse -Filter '*.jar' |
    Where-Object FullName -NotMatch 'yajsw|Extensions[\\/]BinAbsInspector' | ForEach-Object FullName)
$jars += @(Get-ChildItem (Join-Path $repoRoot 'lib') -Filter '*.jar' | ForEach-Object FullName)
if ($DependencyDir) {
    $jars += @(Get-ChildItem (Resolve-Path -LiteralPath $DependencyDir).Path -Filter '*.jar' |
        Where-Object Name -ne 'BinAbsInspector.jar' | ForEach-Object FullName)
}
$classpath = ($jars -join [IO.Path]::PathSeparator).Replace('\', '/')
$sources = Get-ChildItem (Join-Path $repoRoot 'src/main/java'), (Join-Path $repoRoot 'ghidra_scripts') `
    -Recurse -Filter '*.java' | ForEach-Object { '"' + $_.FullName.Replace('\', '/') + '"' }
$arguments = @('-encoding', 'UTF-8', '-proc:none', '-classpath', ('"' + $classpath + '"'),
    '-d', ('"' + $classes.Replace('\', '/') + '"')) + $sources
$argumentFile = Join-Path $buildRoot 'javac-args.txt'
[IO.File]::WriteAllLines($argumentFile, [string[]]$arguments, [Text.UTF8Encoding]::new($false))

# 使用目标 JDK 编译源码，构建失败时停止，不覆盖已安装插件。
& (Join-Path $javaRoot 'bin/javac.exe') '-J-Duser.language=en' "@$argumentFile"
if ($LASTEXITCODE -ne 0) { throw 'BinAbsInspector compilation failed.' }
$jar = Join-Path $buildRoot 'BinAbsInspector.jar'
& (Join-Path $javaRoot 'bin/jar.exe') --create --file $jar -C $classes . `
    -C (Join-Path $repoRoot 'src/main/resources') .
if ($LASTEXITCODE -ne 0) { throw 'BinAbsInspector packaging failed.' }
Write-Output $jar
