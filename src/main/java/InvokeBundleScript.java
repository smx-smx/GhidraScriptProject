/**
 * A Ghidra script to chainload another Script bundled in an OSGI module
 * Written by Stefano Moioli <smxdev4@gmail.com>
 */
import generic.stl.Pair;
import ghidra.app.script.GhidraScript;
import ghidra.app.tablechooser.AddressableRowObject;
import ghidra.app.tablechooser.StringColumnDisplay;
import ghidra.app.tablechooser.TableChooserDialog;
import ghidra.app.tablechooser.TableChooserExecutor;
import ghidra.program.model.address.Address;
import org.osgi.framework.Bundle;
import org.osgi.framework.wiring.BundleWiring;

import java.io.PrintWriter;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.util.Collection;
import java.util.Objects;
import java.util.stream.Stream;

public class InvokeBundleScript extends GhidraScript {
    /**
     * This class represents a row in the table
     * It also stores a reference to the [Bundle,Class] pair that will be used to invoke the script
     */
    private static class ScriptRowObject implements AddressableRowObject {
        private final Bundle bundle;
        private final Class scriptClass;

        public ScriptRowObject(Bundle bundle, Class scriptClass){
            this.bundle = bundle;
            this.scriptClass = scriptClass;
        }

        @Override
        public Address getAddress() {
            return Address.NO_ADDRESS;
        }
    }

    /** this is required to avoid the OSGI scanner parsing Class.forName constants and emitting duplicate imports */
    private static Class getClassFromParts(String... parts) throws Exception {
        return Class.forName(String.join(".", parts));
    }

    /**
     * scans for Ghidra scripts in the default scripts package in the given bundle
     * @param bundle    the bundle to search in
     * @return          a collection of [Bundle, Class] pairs for each detected GhidraScript
     */
    private Stream<? extends Pair<Bundle, Class<?>>> collectClasses(Bundle bundle){
        var wiring = bundle.adapt(BundleWiring.class);
        return wiring.listResources("/", "*.class", BundleWiring.FINDENTRIES_RECURSE)
                .stream().filter(path -> bundle.getEntry(path) != null)
                .map(path -> {
                    // remove .class and convert to class name
                    return path.replace('/', '.').substring(0, path.length() - 6);
                })
                .map(it -> {
                    println("path: " + it);
                    try {
                        return new Pair<Bundle, Class<?>>(bundle, bundle.loadClass(it));
                    } catch (ClassNotFoundException|NoClassDefFoundError e) {
                        e.printStackTrace();
                        return null;
                    }
                })
                .filter(Objects::nonNull)
                .filter(p -> {
                    println("class: " + p.second.getName());
                    return GhidraScript.class.isAssignableFrom(p.second);
                });
    }

    /**
     * This function constructs a table dialogue with [Bundle] and [Script] columns
     * @param dlg
     */
    private void configureTableColumns(TableChooserDialog dlg){
        var bundleName = new StringColumnDisplay(){
            @Override
            public String getColumnValue(AddressableRowObject addressableRowObject) {
                var row = (ScriptRowObject)addressableRowObject;
                return row.bundle.getSymbolicName();
            }

            @Override
            public String getColumnName() {
                return "Bundle";
            }
        };

        var scriptName = new StringColumnDisplay(){
            @Override
            public String getColumnValue(AddressableRowObject addressableRowObject) {
                var row = (ScriptRowObject)addressableRowObject;
                return row.scriptClass.getName();
            }

            @Override
            public String getColumnName() {
                return "Script";
            }
        };

        dlg.addCustomColumn(bundleName);
        dlg.addCustomColumn(scriptName);
    }

    public void run() throws Exception {
        var thisScript = this;
        var dlg = createTableChooserDialog("Choose a script", new TableChooserExecutor() {
            @Override
            public String getButtonName() {
                return "Run";
            }

            /**
             * this function is invoked when the user selects a script to run
             * @param addressableRowObject  the chosen script
             * @return
             */
            @Override
            public boolean execute(AddressableRowObject addressableRowObject) {
                var row = (ScriptRowObject)addressableRowObject;

                Class scriptClass = null;
                try {
                    scriptClass = row.bundle.loadClass(row.scriptClass.getName());
                } catch (ClassNotFoundException e) {
                    e.printStackTrace();
                }

                GhidraScript script = null;
                if(scriptClass != null) {
                    /**
                     * Retrieve and call the GhidraScript constructor
                     */
                    PrintWriter writer;
                    try {
                        Constructor<GhidraScript> ctor;
                        ctor = scriptClass.getConstructor(GhidraScript.class);
                        script = ctor.newInstance(thisScript);
                    } catch (NoSuchMethodException
                            | InvocationTargetException
                            | InstantiationException
                            | IllegalAccessException e
                    ) {
                        e.printStackTrace();
                        return false;
                    }

                    /**
                     * Execute the script while passing through the current script's environment
                     */
                    try {
                        script.execute(
                                thisScript.getState(),
                                thisScript.getMonitor(),
                                thisScript.writer
                        );
                    } catch (Exception e) {
                        throw new RuntimeException(e);
                    }
                }

                if(script == null){
                    thisScript.printerr(String.format("Couldn't find script '%s'", row.scriptClass.getName()));
                    return false;
                }
                return true;
            }
        });
        configureTableColumns(dlg);

        /**
         * When loading plugins, Ghidra generates an OSGI bundle on the fly
         * It scans for any packages required by the script and emits them as imported dependencies in the generated MANIFEST.MF
         * the problem is that, by referencing "ghidra.app.plugin" directly, it gets appended twice and the script will fail to load.
         * this happens because Ghidra always emits "ghidra.app.plugin" as an implicit dependency for every GhidraScript.
         *
         * We can work around this by using Class.forName instead of a package import.
         * However, it looks like the dependency scanner is smart enough to detect imported packages from string constants used in Class.forName
         * that's why we need to fool the scanner by building the class names on the fly.
         *
         * Even if some of these classes are actually public, we need to use them indirectly through reflection
         */
        var cGhidraScriptUtil = getClassFromParts("ghidra", "app", "script", "GhidraScriptUtil");
        var cGhidraBundleHost = getClassFromParts("ghidra", "app", "plugin", "core", "osgi", "BundleHost");
        var cGhidraBundle = getClassFromParts("ghidra", "app", "plugin", "core", "osgi", "GhidraBundle");

        /**
         * Get the Ghidra bundle host and query loaded bundles
         */
        var host = cGhidraScriptUtil.getDeclaredMethod("getBundleHost").invoke(null);
        var bundles = (Collection<Object>) cGhidraBundleHost.getDeclaredMethod("getGhidraBundles").invoke(host);
        var bundleGetter = cGhidraBundle.getDeclaredMethod("getOSGiBundle");

        /**
         * Probe each loaded bundle for available scripts and populate the table dialogue
         */
        bundles.stream().map(b -> {
                    try {
                        return (Bundle)bundleGetter.invoke(b);
                    } catch (Exception e) {
                        e.printStackTrace();
                        return null;
                    }
                }).filter(Objects::nonNull)
                .flatMap(this::collectClasses)
                .forEach(p -> {
                    var row = new ScriptRowObject(p.first, p.second);
                    dlg.add(row);
                });

        dlg.show();
    }
}
