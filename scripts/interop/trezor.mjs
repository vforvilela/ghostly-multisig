// Talks to trezor-user-env's controller (ws://localhost:9001): node trezor.mjs '<json command>' ['<json command>' ...]
// Prints each response. Used by scripts/interop/hardware.mjs; also handy by hand, e.g.
//   node scripts/interop/trezor.mjs '{"type":"emulator-press-yes"}'
export async function controller(commands, url = "ws://localhost:9001") {
  const ws = new WebSocket(url);
  await new Promise((ok, fail) => ((ws.onopen = ok), (ws.onerror = fail)));
  const replies = [];
  let pending = null;
  ws.onmessage = (e) => {
    const msg = JSON.parse(e.data);
    if (msg.type === "client" || msg.id === undefined) return; // the welcome message
    pending?.(msg);
  };
  for (const [i, cmd] of commands.entries()) {
    const reply = await new Promise((ok) => {
      pending = ok;
      ws.send(JSON.stringify({ id: i + 1, ...cmd }));
    });
    if (reply.success === false) throw new Error(`${cmd.type}: ${reply.error}`);
    replies.push(reply);
  }
  ws.close();
  return replies;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  for (const r of await controller(process.argv.slice(2).map((a) => JSON.parse(a)))) console.log(JSON.stringify(r));
}
