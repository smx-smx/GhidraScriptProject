#!/usr/bin/env -S bash
GHIDRA_PATH="/G/ghidra_11.0_PUBLIC"
PRJ_GROUP_ID="com.smx"
PRJ_ARTIFACT_ID="sample"
PRJ_VERSION="1.0-SNAPSHOT"
PRJ_OUT_DIR="out"

for var in GHIDRA_PATH PRJ_GROUP_ID PRJ_ARTIFACT_ID PRJ_VERSION PRJ_OUT_DIR; do
	if [ -z "${!var}" ]; then
		>&2 echo "Required variable ${var} is not set"
		exit 1
	fi
done

[ -e "${PRJ_OUT_DIR}" ] && rm -r "${PRJ_OUT_DIR}"

echo "[+] Installing archetype ..."
mvn -f pom.xml install

echo ""
echo "[+] Generating project ..."
mvn -f pom.xml archetype:generate \
	-DarchetypeGroupId=com.smx \
	-DarchetypeArtifactId=ghidra-script \
	-DarchetypeVersion=1.0-SNAPSHOT \
	-DinteractiveMode=false \
	-DoutputDirectory="${PRJ_OUT_DIR}" \
	-DgroupId="${PRJ_GROUP_ID}" \
	-DartifactId="${PRJ_ARTIFACT_ID}" \
	-Dversion="${PRJ_VERSION}" \
	-DghidraPath="${GHIDRA_PATH}"

echo ""
echo "[+] Building project ..."
mvn -f "${PRJ_OUT_DIR}/${PRJ_ARTIFACT_ID}/pom.xml" package

bundle_path="${PRJ_OUT_DIR}/${PRJ_ARTIFACT_ID}/target/${PRJ_ARTIFACT_ID}-${PRJ_VERSION}.jar"
if [ -f "${bundle_path}" ]; then
	echo "== BUILD SUCCESS =="
	echo "Ghidra bundle: ${bundle_path}"
else
	>&2 echo "== BUILD FAILURE =="
fi
