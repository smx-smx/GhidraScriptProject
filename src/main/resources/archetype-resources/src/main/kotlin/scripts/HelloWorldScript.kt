package ${groupId}.${artifactId}.scripts

import ghidra.app.script.GhidraScript
import java.io.PrintWriter

class HelloWorldScript(s: GhidraScript) : GhidraScript() {
    /** inherit the script state **/
    init {
        val writer = s.javaClass.superclass.getDeclaredField("writer")
            .also { it.isAccessible = true }
            .get(s) as PrintWriter

        this.set(s.state, s.monitor, writer)
    }

    override fun run() {
        this.println("Hello World from Kotlin!")
    }
}