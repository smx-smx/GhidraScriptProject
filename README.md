## GhidraScriptProject
This project illustrates how to (ab)use Ghidra to run precompiled scripts from external .jar files.

### Features
This project enables you to write Ghidra Scripts using your favourite IDE, using any additional library from maven and/or
any maven build plugin.

This in turn makes it possible to use Kotlin, Scala, or any other JVM language.

### How is this achieved
Ghidra supports loading scripts in .java (source) form from directories as well as script bundles (OSGI bundles).

It doesn't however support loading compiled scripts (.class) out of the box.

These steps are involved in working around this limitation:


1. Install the archetype after cloning this repository
```console
mvn install
```
2. Generate a new project (replace variables with your desired values)

IMPORTANT: Set ${ghidra_path} to your Ghidra installation directory
```console
mvn archetype:generate \
	-DarchetypeGroupId=com.smx \
	-DarchetypeArtifactId=ghidra-script \
	-DarchetypeVersion=1.0-SNAPSHOT \
	-DinteractiveMode=false \
	-DoutputDirectory=${project_output_directory} \
	-DgroupId="${project_group_id}" \
	-DartifactId="${project_artifact_id}" \
	-Dversion="${project_version}" \
	-DghidraPath="${ghidra_path}"
```

3. Build the generated project
```console
cd "${project_output_directory}/${project_artifact_id}"
mvn package
```

4. Load the generated Jar in Ghidra. It should show as green in the Scripts Manager
If it fails loading, make sure any Maven Dependency is Added to the `<Import-Package>` section of `maven-bundle-plugin`.

This is required because `maven-shade-plugin` will bundle the dependency within the generated JAR, and there is currently no mechanism to automatically exclude such dependencies from the generated Manifest

Example (excluding the Kotlin standard library)
```xml
<groupId>org.apache.felix</groupId>
<artifactId>maven-bundle-plugin</artifactId>
<version>5.1.9</version>
<extensions>true</extensions>
<configuration>
	<instructions>
		<Export-Package>com.smx.scripts</Export-Package>
		<Import-Package>!kotlin;!kotlin.*;*</Import-Package>
		<Bundle-Activator>com.smx.SmxBundleActivator</Bundle-Activator>
	</instructions>
</configuration>
```

5. Copy `./src/main/java/InvokeBundleScript.java` to your Ghidra scripts directory, e.g. `$HOME/ghidra_scripts`

6. Run `InvokeBundleScript` from the Scripts Manager
