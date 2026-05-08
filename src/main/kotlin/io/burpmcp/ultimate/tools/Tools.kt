package io.burpmcp.ultimate.tools

import burp.api.montoya.MontoyaApi
import io.burpmcp.ultimate.mcp.EditorRegistry
import io.burpmcp.ultimate.mcp.EventBus
import io.burpmcp.ultimate.mcp.HandleStore
import io.burpmcp.ultimate.mcp.InterceptQueue
import io.burpmcp.ultimate.mcp.Progress
import io.burpmcp.ultimate.mcp.ToolRegistry

fun registerAllTools(
    reg: ToolRegistry,
    api: MontoyaApi,
    handles: HandleStore,
    events: EventBus,
    intercept: InterceptQueue,
    editors: EditorRegistry,
    progress: Progress,
) {
    HttpTools.register(reg, api)
    ProxyTools.register(reg, api)
    RepeaterTools.register(reg, api)
    IntruderTools.register(reg, api)
    ScannerTools.register(reg, api, handles)
    CollaboratorTools.register(reg, api)
    SitemapTools.register(reg, api, handles)
    ScopeTools.register(reg, api)
    UtilTools.register(reg, api)
    UtilExtTools.register(reg, api)
    ProjectTools.register(reg, api)
    PersistenceTools.register(reg, api, handles)
    WebSocketTools.register(reg, api, handles)
    OrganizerTools.register(reg, api)
    LoggerTools.register(reg, api)
    BurpSuiteTools.register(reg, api)
    ComparerTools.register(reg, api)
    DecoderTools.register(reg, api)

    CompositeTools.register(reg, api, handles)
    AnnotationTools.register(reg, api, handles)
    EditorTools.register(reg, api, editors, handles)
    InterceptTools.register(reg, api, intercept)
    EventTools.register(reg, events)

    // v4 additions
    GraphQLTools.register(reg, api)
    OAuthTools.register(reg, api)
    JwtTools.register(reg, api)
    DiffTools.register(reg, api, handles)
    BulkTools.register(reg, api, progress)
    JsAnalysisTools.register(reg, api)

    // Reflection escape hatch last so other tools' richer schemas show first.
    ReflectTools.register(reg, api, handles)
}
