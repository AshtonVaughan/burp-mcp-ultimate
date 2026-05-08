# Extension Bridge Smoke Prompt

Paste this into your MCP-connected Claude session after reloading the extension in Burp. It validates the bridge against the live extensions you have installed and produces a status table you can paste back to me.

---

````
You have mcp__burp__bridge_* and per-extension wrapper tools. Run a smoke test
of the extension bridge and report results in a Markdown table.

Output legend: ✓ working | ⚠ loaded but wrapper failed (paste exact error)
              | ⊘ extension not loaded | ✗ unexpected error

Tests, in order. Run them all even if individual ones fail. Capture every
error message verbatim.

### Discovery (1)
1. bridge_list_extensions — capture the count and the labels/known_classes
   of every extension that came back.

### Logger++ (3)
2. loggerpp_status — note loaded=true/false and entry_count.
3. loggerpp_get_entries with max=10 — note the count returned and one
   field name from a row.
4. loggerpp_search with filter="example" max=10 — note the count and
   that the search ran without error.

### Hackvertor (3)
5. hackvertor_status — note loaded=true/false and the candidate_classes
   it found.
6. hackvertor_evaluate with input="<@base64>hello<@/base64>" — expect
   "aGVsbG8=" (base64 of "hello").
7. hackvertor_evaluate with input="<@hex>burp<@/hex>" — expect a
   hex-encoded string.

### Param Miner (1)
8. param_miner_status — note loaded=true/false and which candidate
   classes it found.

### Turbo Intruder (1)
9. turbo_intruder_status — note loaded=true/false and candidate classes.

### Generic bridge against Logger++ (3)
10. bridge_inspect_class with extension="Logger++" and
    class="com.nccgroup.loggerplusplus.LoggerPlusPlus" — note the
    method count returned.
11. bridge_inspect_class with extension="Logger++" and
    class="com.nccgroup.loggerplusplus.logentry.LogEntry" — note
    available fields.
12. bridge_invoke_static with extension="Logger++" and method
    matching whatever static method LoggerPlusPlus exposes (look at
    the inspect output from #10) — best-effort, may not have a
    callable static.

### Generic bridge against Hackvertor (1)
13. bridge_inspect_class with extension="Hackvertor" and
    class="burp.parser.Convertors" (or whichever candidate class
    appeared in #5) — note the method count.

### Cross-validation (1)
14. bridge_refresh — confirm it returns rescanned=true and the count
    matches #1.

After all 14 tests, output the table and below it list every ⚠ and ✗ row
with the full error message.
````

---

## What I expect to see

If everything works:
- 14 rows in the table
- ✓ on tests 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 14
- ⚠ or ✓ on test 12 (depends on Logger++ exposing a callable static method)

If Logger++ or Hackvertor's class structure has shifted, you'll see ⚠ rows. Paste them back and I'll patch the wrappers - the typical fix is a one-line update to the candidate class names list in `ExtensionWrappers.kt` or `ExtensionBridge.kt :: KNOWN_EXTENSION_CLASSES`.

## If discovery itself fails

If `bridge_list_extensions` returns 0 extensions, the thread-walking discovery isn't finding the extension classloaders on your Burp build. Workaround: tell me the output of:

```
bridge_invoke_static with extension=<any of yours> and method="java.lang.Thread.getAllStackTraces"
```

(That'll fail but the error path will tell us what's actually visible.)
