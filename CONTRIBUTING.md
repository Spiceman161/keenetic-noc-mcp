# Contributing

Bug reports and pull requests are welcome.

## Running it

```sh
npm ci
npm run typecheck
npm test
npm run build
git diff --check
```

Tests run against sanitized fixtures; no router is required. The optional
smoke tests are read-only and are never run in CI:

```sh
KEENETIC_TEST_HOST=... KEENETIC_TEST_PASSWORD=... npm run smoke
KEENETIC_TEST_URL=https://rci.example.net/rci/ KEENETIC_TEST_USER=... KEENETIC_TEST_PASSWORD=... npm run smoke:remote
```

Do not run a live mutation during a test or smoke check. Never commit captured
router responses; retain only sanitized shapes and counts in fixtures.

## The one thing that matters most

**Verify against the router, not against your model of it.**

Keenetic answers a wrong field name with `{}`, HTTP 200, no error, and nothing
changed. It is indistinguishable from success. Two real bugs here passed every
unit test and only surfaced against live hardware, because the tests asserted
what the author assumed the router does.

So: read every write back through whichever view actually exposes the field, and
say in the pull request which model and KeeneticOS version you checked it on.
`src/tools/write.ts` is the pattern. `docs/rci-api.md` collects the traps.

If a change cannot be verified without hardware you do not have, say so. That is
a normal answer here and better than a confident guess.

## Never commit real network data

A test scans the whole repository for anything shaped like a real MAC address, a
private IP or key material, and it will fail your build. It exists because those
have leaked here before, including from a fixture captured off a live router.

Device names and SSIDs have no detectable shape, so nothing catches those.
Read your own diff before pushing it.

Before opening a pull request, run the commands above and describe the router
model, KeeneticOS version, and only the read-only evidence you used. Call out
any remote path that you could not test.

## Style

Match the surrounding code. Comments explain why something is the way it is,
especially when it looks wrong: most of them are load-bearing and record a trap
that cost someone an afternoon.

Plain ASCII hyphens, no em dashes, anywhere.

Commit messages say what changed and why it had to change that way.

## Adding another vendor

Please open an issue first. The code is RCI-shaped throughout, and a vendor
boundary with one implementation behind it would be a guess. A separate
repository that borrows the tool shapes, the verified-write pattern and the
skills format is the cheaper start, and the parts worth sharing can be extracted
once there are two working servers to compare.
