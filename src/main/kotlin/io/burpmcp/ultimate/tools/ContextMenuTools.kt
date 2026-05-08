package io.burpmcp.ultimate.tools

import burp.api.montoya.MontoyaApi
import burp.api.montoya.ui.contextmenu.AuditIssueContextMenuEvent
import burp.api.montoya.ui.contextmenu.ContextMenuEvent
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider
import burp.api.montoya.ui.contextmenu.WebSocketContextMenuEvent
import io.burpmcp.ultimate.mcp.EditorRegistry
import io.burpmcp.ultimate.mcp.EventBus
import io.burpmcp.ultimate.mcp.HandleStore
import java.awt.Component
import javax.swing.JMenuItem

/**
 * Adds "AI" right-click items in Burp:
 *  - "AI: capture editor"      stashes the active MessageEditor
 *  - "AI: handle these items"  stores selected requests/responses as handles
 *  - "AI: handle this issue"   stores selected scan issue as a handle
 *
 * Each click pushes an event on the `context_menu` channel so subscribed
 * agents see it immediately and can react with proxy_history etc.
 */
object ContextMenuTools {

    fun install(api: MontoyaApi, editors: EditorRegistry, handles: HandleStore, events: EventBus) {

        api.userInterface().registerContextMenuItemsProvider(object : ContextMenuItemsProvider {

            override fun provideMenuItems(event: ContextMenuEvent): List<Component> {
                val items = ArrayList<Component>()

                event.messageEditorRequestResponse().ifPresent { editor ->
                    val item = JMenuItem("AI: capture this editor").apply {
                        addActionListener {
                            editors.set(editor, "context_menu")
                            events.pushExternal("context_menu", mapOf(
                                "kind"      to "editor_captured",
                                "selection" to editor.selectionContext().name,
                                "caret"     to editor.caretPosition(),
                                "url"       to (editor.requestResponse().request()?.url() ?: ""),
                            ))
                        }
                    }
                    items.add(item)
                }

                val selected = event.selectedRequestResponses()
                if (selected.isNotEmpty()) {
                    val item = JMenuItem("AI: send ${selected.size} item(s)").apply {
                        addActionListener {
                            val ids = selected.map { handles.put(it) }
                            events.pushExternal("context_menu", mapOf(
                                "kind"    to "request_response_handles",
                                "count"   to ids.size,
                                "handles" to ids,
                                "urls"    to selected.map { it.request()?.url() ?: "" },
                            ))
                        }
                    }
                    items.add(item)
                }

                return items
            }

            override fun provideMenuItems(event: AuditIssueContextMenuEvent): List<Component> {
                val issues = event.selectedIssues()
                if (issues.isEmpty()) return emptyList()
                val item = JMenuItem("AI: send ${issues.size} issue(s)").apply {
                    addActionListener {
                        val ids = issues.map { handles.put(it) }
                        events.pushExternal("context_menu", mapOf(
                            "kind"     to "issue_handles",
                            "count"    to ids.size,
                            "handles"  to ids,
                            "names"    to issues.map { it.name() },
                            "severity" to issues.map { it.severity().name },
                        ))
                    }
                }
                return listOf(item)
            }

            override fun provideMenuItems(event: WebSocketContextMenuEvent): List<Component> {
                val item = JMenuItem("AI: capture WS frame").apply {
                    addActionListener {
                        events.pushExternal("context_menu", mapOf(
                            "kind" to "ws_frame_selected",
                        ))
                    }
                }
                return listOf(item)
            }
        })
    }
}
