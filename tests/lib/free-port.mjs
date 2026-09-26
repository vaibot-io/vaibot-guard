import net from "node:net";

/**
 * Ask the kernel for a free loopback port, then release it for the fixture's
 * guard to bind.
 *
 * Each fixture boots its own sandboxed daemon (its own HOME, workspace and log
 * dir) because policy, mode and bundle are all read at boot. That is separate
 * from the product's one-guard-per-machine rule, which the guard.json
 * rendezvous and the service's refusal to double-bind enforce.
 *
 * Fixtures used to pick a random port out of a hand-assigned range, and the
 * ranges overlapped: guard-service and guard-containment both drew from
 * 39200-41199, guard-signed-policy and guard-hermes-vocab both from
 * 41200-43199, guard-host-bypass and guard-ephemeral-approvals both from
 * 43200-45199, plus four partial overlaps. Files run in parallel and
 * host-bypass alone redraws on each of its 11 boots, so collisions were
 * routine: the loser exits EADDRINUSE (vaibot-guard-service.mjs), never reaches
 * /health, and the file fails with "should start".
 *
 * Asking the kernel removes the guessing, and unlike a hand-picked band it
 * cannot collide with an unrelated process either, since the kernel only offers
 * a port that is free.
 */
export function reservePort() {
  return new Promise((resolve, reject) => {
    const srv = net.createServer();
    srv.unref();
    srv.once("error", reject);
    srv.listen(0, "127.0.0.1", () => {
      const { port } = srv.address();
      srv.close(() => resolve(port));
    });
  });
}
