package ${groupId}.scripts

import ghidra.app.script.GhidraScript
import java.io.PrintWriter

class HelloWorldScript(s: GhidraScript? = null) : GhidraScript() {
    init {
        if (s != null) {
            /** inherit the script state **/
            val writer = s.javaClass.superclass.getDeclaredField("writer")
                .also { it.isAccessible = true }
                .get(s) as PrintWriter

            this.set(s.state, s.monitor, writer)
        }
    }

    override fun run() {
        this.println("Hello World from Kotlin!")
    }
}