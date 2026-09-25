import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';

const skill = readFileSync(new URL('../../plugins/keenetic/skills/keenetic-vpn/SKILL.md', import.meta.url), 'utf8');
const multiInterface = skill.split('For explicitly requested throughput across multiple WireGuard/VPN interfaces,')[1]
  ?.split('If `component-not-installed`')[0];

describe('VPN multi-interface active-diagnostic guidance', () => {
  it('preflights each interface sequentially against the authorized server with the exact source', () => {
    expect(multiInterface).toBeDefined();
    expect(multiInterface).toMatch(/sequentially, never in parallel/);
    expect(multiInterface).toMatch(/Before each interface's\s+`iperf3`/);
    expect(multiInterface).toMatch(/exactly one small IPv4 `ping` \(count 1\) to the same authorized\s+iPerf3 server host with that exact `source_interface`/);
    expect(multiInterface).toMatch(/does not establish reachability.*mark that interface not characterized by\s+iPerf3 and skip its iPerf3 call/s);
    expect(multiInterface).toMatch(/continue to the next interface only if no\s+active diagnostic has uncertain router-side state/);
    expect(multiInterface).toMatch(/successful ping is only\s+a preflight, not proof of physical egress, WireGuard health, or expected\s+throughput/);
  });

  it('reports available native rates separately without increasing active traffic', () => {
    expect(multiInterface).toMatch(/`throughput: unknown` is not a\s+claim that there is no useful speed evidence/);
    expect(multiInterface).toMatch(/`nativeRoleObservations`\s+and report observed `sender` and `receiver` `bitrateMbps` separately when\s+present/);
    expect(multiInterface).toMatch(/without inventing missing rates or a single true speed/);
    expect(multiInterface).toMatch(/1048576-byte\/10000-ms conservative choice per interface/);
    expect(multiInterface).toMatch(/no larger\s+traffic, parallel calls, retries, or automatic server selection/);
  });

  it('stops even the next ping on uncertain cancellation without indirect termination claims', () => {
    expect(skill).toMatch(/`active_diagnostic_uncertain`,\s+`routerTermination: unknown`, or equivalent uncertain cancellation, stop all\s+further active diagnostics immediately, including pings for remaining\s+interfaces/);
    expect(skill).toMatch(/Do not use routes, WireGuard counters, logs, or broad\s+`show\/processes` as indirect proof of termination/);
    expect(skill).toMatch(/Without an exact documented\s+termination check, return the partial report and require operator intervention\s+or runtime restart only under the existing documented policy/);
  });
});
