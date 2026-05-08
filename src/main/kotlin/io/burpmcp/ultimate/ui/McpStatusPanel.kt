package io.burpmcp.ultimate.ui

import io.burpmcp.ultimate.mcp.EventBus
import io.burpmcp.ultimate.mcp.HandleStore
import io.burpmcp.ultimate.mcp.InterceptQueue
import io.burpmcp.ultimate.mcp.SessionRegistry
import io.burpmcp.ultimate.mcp.SseHub
import java.awt.BorderLayout
import java.awt.Dimension
import java.awt.GridLayout
import javax.swing.*

class McpStatusPanel(
    url: String,
    tokenSet: Boolean,
    private val toolCount: Int,
    private val resourceCount: Int,
    private val promptCount: Int,
    private val handles: HandleStore,
    private val events: EventBus,
    private val sseHub: SseHub,
    private val intercept: InterceptQueue,
    private val sessions: SessionRegistry,
) : JPanel(BorderLayout(8, 8)) {

    private val countLabel    = JLabel("Sessions: 0   Total tool calls: 0")
    private val handleLabel   = JLabel("Handles: 0")
    private val sseLabel      = JLabel("SSE clients: 0")
    private val interceptLbl  = JLabel("Intercept: OBSERVE   pending: 0")
    private val channelsLabel = JLabel("Event channels: ()")

    private val sessionsModel = object : javax.swing.table.AbstractTableModel() {
        private val cols = arrayOf("Session", "Created", "Last seen", "Calls")
        private var data: List<Map<String, Any?>> = emptyList()
        fun update(items: List<Map<String, Any?>>) {
            data = items; fireTableDataChanged()
        }
        override fun getRowCount() = data.size
        override fun getColumnCount() = cols.size
        override fun getColumnName(i: Int) = cols[i]
        override fun getValueAt(row: Int, col: Int): Any {
            val r = data[row]
            return when (col) {
                0 -> r["id"] ?: ""
                1 -> (r["created_at"]?.toString() ?: "").take(19)
                2 -> (r["last_seen"]?.toString() ?: "").take(19)
                else -> r["calls"] ?: 0
            }
        }
    }

    init {
        border = BorderFactory.createEmptyBorder(12, 12, 12, 12)

        val header = JPanel(GridLayout(0, 1, 4, 4)).apply {
            add(JLabel("burp-mcp-ultimate v0.2.0").apply { font = font.deriveFont(font.size * 1.5f) })
            add(JLabel("MCP endpoint:  $url"))
            add(JLabel("Bearer token:  ${if (tokenSet) "ENFORCED" else "OFF (set BURP_MCP_TOKEN)"}"))
            add(JLabel("Surfaces: $toolCount tools  /  $resourceCount resources  /  $promptCount prompts"))
            add(countLabel)
            add(handleLabel)
            add(sseLabel)
            add(interceptLbl)
            add(channelsLabel)
        }
        add(header, BorderLayout.NORTH)

        val table = JTable(sessionsModel).apply {
            autoResizeMode = JTable.AUTO_RESIZE_LAST_COLUMN
            preferredScrollableViewportSize = Dimension(900, 360)
            columnModel.getColumn(0).preferredWidth = 80
            columnModel.getColumn(1).preferredWidth = 180
            columnModel.getColumn(2).preferredWidth = 180
        }
        add(JScrollPane(table), BorderLayout.CENTER)

        // Refresh on a timer; cheap.
        Timer(1000) {
            val list = sessions.list()
            sessionsModel.update(list)
            val totalCalls = list.sumOf { (it["calls"] as? Number)?.toLong() ?: 0L }
            countLabel.text    = "Sessions: ${sessions.size}   Total tool calls: $totalCalls"
            handleLabel.text   = "Handles: ${handles.size}"
            sseLabel.text      = "SSE clients: ${sseHub.activeCount}"
            interceptLbl.text  = "Intercept: ${intercept.mode.name}   pending: ${intercept.pendingCount()}"
            channelsLabel.text = "Event channels: ${events.listChannels()}"
        }.start()
    }
}
