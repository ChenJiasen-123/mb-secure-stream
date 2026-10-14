///|
pub fn inspect(text : String) -> String {
  let parsed = @log.parse_events(text)
  let header = match parsed.header {
    Some(value) => value
    None => {
      let report : Json = {
        "valid": false,
        "reason": "missing or unsupported header",
      }
      return report.stringify()
    }
  }
  if parsed.errors.length() != 0 || parsed.partial_tail {
    let report : Json = {
      "valid": false,
      "reason": "invalid event or partial tail",
    }
    return report.stringify()
  }
  let mut previous = 0
  for event in parsed.events {
    if event.sequence() != previous + 1 {
      let report : Json = {
        "valid": false,
        "reason": "non-contiguous event sequence",
      }
      return report.stringify()
    }
    previous = event.sequence()
  }
  let session = @log.session_from_parse(
    parsed,
    id=header.id,
    system_prompt=header.system_prompt,
  )
  let report : Json = {
    "valid": true,
    "sessionId": session.id().value(),
    "events": parsed.events.length(),
    "lastSequence": session.last_sequence(),
    "chatMessages": session.chat_messages().length(),
  }
  report.stringify()
}

///|
/// Fixture generated with upstream public constructors and JSON serializers.
pub fn make_demo() -> String {
  let session = @session.Session(
      @session.SessionId("mbss-openseek-demo"),
      system_prompt="Synthetic public test only.",
    )
    .append(
      User(UserMessage(Content([Text("read synthetic.txt")]))),
      unix_ms=1L,
    )
    .append(Assistant(AssistantMessage("synthetic response")), unix_ms=2L)
    .append(
      Tool(
        ToolResult(tool_call_id="demo-call", tool_name="read", content=[
          Text("synthetic contents"),
        ]),
      ),
      unix_ms=3L,
    )
    .append(Runtime(RuntimeNotice("synthetic notice")), unix_ms=4L)
    .append(Terminal(Finished("synthetic completion")), unix_ms=5L)
  let header : @log.SessionFileHeader = {
    id: session.id().value(),
    system_prompt: session.system_prompt(),
  }
  let out = StringBuilder()
  out.write_string(ToJson::to_json(header).stringify())
  out.write_char('\n')
  for event in session.events() {
    out.write_string(ToJson::to_json(event).stringify())
    out.write_char('\n')
  }
  out.to_string()
}
