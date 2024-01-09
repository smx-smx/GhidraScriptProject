set GHIDRA_PATH=G:\ghidra_11.0_PUBLIC
set PRJ_GROUP_ID=com.smx
set PRJ_ARTIFACT_ID=sample
set PRJ_VERSION=1.0-SNAPSHOT
set PRJ_OUT_DIR=out

rd /s /q %PRJ_OUT_DIR%
mvn archetype:generate ^
-DarchetypeGroupId=com.smx ^
-DarchetypeArtifactId=ghidra-script ^
-DarchetypeVersion=1.0-SNAPSHOT ^
-DinteractiveMode=false ^
-DoutputDirectory=out ^
-DgroupId=%PRJ_GROUP_ID% ^
-DartifactId=%PRJ_ARTIFACT_ID% ^
-Dversion=%PRJ_VERSION% ^
-DghidraPath=%GHIDRA_PATH% && ^
cd %PRJ_OUT_DIR%\%PRJ_ARTIFACT_ID% && ^
mvn package
