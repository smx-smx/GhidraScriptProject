// comment this when running in Ghidra
package scripts;

/**
 * A Ghidra script to chainload another Script bundled in an OSGI module
 * Scripts must be placed in the /scripts package inside the bundle
 *
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

    private Stream<? extends Pair<Bundle, Class<?>>> collectClasses(Bundle bundle){
        var wiring = bundle.adapt(BundleWiring.class);
        return wiring.listResources("/scripts", "*.class", BundleWiring.FINDENTRIES_RECURSE)
                .stream().filter(path -> bundle.getEntry(path) != null)
                .map(path -> {
                    // remove .class and convert to class name
                    return path.replace('/', '.').substring(0, path.length() - 6);
                })
                .map(it -> {
                    println("path: " + it);
                    try {
                        return new Pair<Bundle, Class<?>>(bundle, bundle.loadClass(it));
                    } catch (ClassNotFoundException e) {
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

        var cGhidraScriptUtil = getClassFromParts("ghidra", "app", "script", "GhidraScriptUtil");
        var cGhidraBundleHost = getClassFromParts("ghidra", "app", "plugin", "core", "osgi", "BundleHost");
        var cGhidraBundle = getClassFromParts("ghidra", "app", "plugin", "core", "osgi", "GhidraBundle");

        var host = cGhidraScriptUtil.getDeclaredMethod("getBundleHost").invoke(null);
        var bundles = (Collection<Object>) cGhidraBundleHost.getDeclaredMethod("getGhidraBundles").invoke(host);
        var bundleGetter = cGhidraBundle.getDeclaredMethod("getOSGiBundle");

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