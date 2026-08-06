# graphify knowledge graph

The repo carries a knowledge graph of itself under `graphify-out/`: entities, cross-file
relationships, community structure, and an EXTRACTED / INFERRED / AMBIGUOUS audit trail so a
reader can tell what was read off the AST from what was guessed by a model.

Day-to-day use is in `CLAUDE.md`. This file covers the two things that are not obvious from
using it: what is committed, and the merge driver you have to install yourself.

## What is committed, and why

```text
graphify-out/cache/semantic/    TRACKED — the LLM extraction pass (~718K tokens to rebuild)
graphify-out/manifest.json      TRACKED — drives incremental `graphify update`
graphify-out/*                  ignored — regenerable at no cost
```

The split is a cost question, not a preference. Semantic extraction runs a model over every
doc, paper and image and is the only expensive part; losing it means paying for it again. AST
extraction is deterministic and free, and `graph.json`, the HTML view and `GRAPH_REPORT.md`
all derive from the cache — so they are rebuilt rather than stored.

Keep code changes and graph rebuilds in **separate commits**. A regenerated `graph.json`
diff is large and mechanical, and mixing it with a real change buries the change.

## The merge driver — you must install this yourself

`.gitattributes` contains:

```text
graphify-out/graph.json merge=graphify
```

That tells git to merge the graph by regenerating it rather than by reconciling JSON lines,
which is the only sane outcome when two branches have both rebuilt it.

**`merge=graphify` is a name, not a definition.** Git resolves it against the *local*
machine's config, and the definition points at an absolute interpreter path, so it cannot be
committed. On a fresh clone, another machine, or CI, the name is simply undefined.

The failure mode is mild but confusing: git prints a warning about an undefined merge driver
and silently falls back to the default merge. You get a conflicted or line-wise-merged
`graph.json`. Nothing is corrupted — the file is derived, so the fix is always to regenerate:

```bash
graphify update .
```

To install the driver (once per machine):

```bash
git config merge.graphify.driver \
  "$(command -v python3) -m graphify merge-driver %O %A %B"
```

If graphify was installed with `uv tool`, point at that interpreter instead — `uv tool run
--from graphifyy python -c 'import sys; print(sys.executable)'` prints the right path.

> `graphifyy` with two y's is **correct** and is not a typo: the PyPI distribution is
> `graphifyy`, and the executable it installs is `graphify`. `uv tool list` shows
> `graphifyy v0.9.x` providing `graphify`. Automated reviewers flag this as a misspelling;
> "fixing" it breaks the command, because there is no `graphify` package to install from.

Verify with `git config --get merge.graphify.driver`. Empty output means the driver is not
installed and you will get the fallback described above.

**CI does not need this.** Nothing in the build reads `graph.json`, so an undefined driver in
CI is harmless. It matters only where humans merge branches locally.

## Rebuilding

```bash
graphify update .                # incremental, AST-only, free
graphify query "<question>"      # scoped subgraph — prefer over grep
graphify path "<A>" "<B>"        # how two things relate
graphify explain "<concept>"     # focused explanation
```

A post-commit hook rebuilds the graph after commits that touch code. It ignores doc-only
changes — run `graphify update .` by hand after a docs pass if you want them reflected.

## What it has actually caught

Worth recording, because the value is not obvious until it happens: the graph found a
duplicate `X-7` requirement ID in `docs/PRD.md` (two rows sharing an ID — invisible to a
reader scanning the table and invisible to CI, but a graph cannot represent it, so the
extractor hit a duplicate node ID and had to split them), and drift between the Helm CRD
bundle and the operator's. Both surfaced as side effects of building the graph rather than as
anything anyone went looking for.
