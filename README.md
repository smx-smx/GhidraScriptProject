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


- Prepare a maven project (this repo) in such a way that it will create an OSGI bundle.
Any dependency not available in Ghidra must be declared in the `<Export-Package>` section of the `maven-bundle-plugin` configuration.
This will instruct the bundler to include a copy of those dependencies.
You can find out which dependencies are required by trying to load the Script and observing the errors related to missing packages.
- Update the `ghidra.path` property of the project to point to your local Ghidra installation. (you might also override it when running Maven via `-Dghidra.path=...`)
- After running the `package` phase, you will find `target/mainModule-1.0-SNAPSHOT-jar-with-dependencies.jar`. This is the bundle that we must load in Ghidra.
In order to do this, navigate to
```
Ghidra Script Manager --> Manage Script Directories --> Add --> select the .jar file
```
- Now that the bundle is loaded, we need a way to launch the scripts contained within it.
To do this, copy `InvokeBundleScript.java` from this repository into your local `ghidra_scripts` directory, normally located in $HOME or %USERPROFILE%
- Refresh the available scripts, and you should see `InvokeBundleScript` within the available scripts.
Running it will scan for all loaded bundles and look for scripts located in `/scripts`, or the `scripts` package in other words.
The package name to look for can be changed in `InvokeBundleScript.java` if desired