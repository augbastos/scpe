# Retrospective: what happened when I asked

[Back to SCPE](../README.md)

This is the author's account, moved from the README to preserve the project's
self-critique. The author reported no external adoption when freezing the project.
The correspondence, quotations, third-party events, and adoption observations below
are retained as that historical account: this repository does not include primary
sources sufficient to independently verify them. They are not evidence of current
third-party policies or measured demand.

The conclusion recorded here was that the original argument did not survive
contact with the maintainers it was built for. The technical artifact remains
inspectable; the account does not establish that maintainers need it.

On 2026-07-28 I asked two of the projects whose AI policies this repository cites how their
own policy is actually checked. I expected "nobody checks." Three answers came back in hours.

**OpenSSL already automates it.** A project member described their CLA service: it reads every
non-trivial commit for the `Assisted-by:` trailer, with `Co-authored-by:` naming a known AI
tool as a backstop, and posts a `cla-check` status. An AI-assisted commit from a contributor
still on CLA 1.0 fails and is held until they re-sign 1.1. Asked whether *presence* of the
trailer is checked for someone already on 1.1:

> Obviously not and we don't enforce it.

They built automation the moment the disclosure carried a **legal consequence**, and
deliberately built none for transparency. That is not a project failing to enforce its policy.
It is a project enforcing the branch that routes somewhere.

**MicroPython checks by eye and reports it works.** A collaborator there:

> I look at more than the checkbox and canned text phrases as some authors add more context.
>
> I seldom find it is omitted, and I can only recall a few cases, most of them when the
> template was circumvented.
>
> Most authors quickly correct when reminded by a human, less so when CI is showing ❌

Three things in that. Omission is rare. The real failure is people going around the template,
which a lint on the checkbox would not catch. And the last line inverts an assumption built
into this design: an automated red check may buy **less** compliance than a person asking.

**A third contributor said the question read as an advert.** Fair — the post carried a link.

### What that killed

- The premise. "Policies exist and nothing enforces them" is false where it mattered most.
- The framing. Level 1 was described as *enforcement* and a *gate*. If a red check produces
  less compliance than a human reminder, "gate" is not merely unnecessary, it is wrong. It is
  a reviewer aid, `require: "false"` is the default, and that is now what the docs say.
- The direction. Maintainers who *are* drowning chose to **reduce input**, not to verify it
  better: the Jazzband collective shut down over AI PR volume, tldraw auto-closes all external
  pull requests, GitHub shipped a switch to disable PRs outright. And curl — the loudest
  AI-slop casualty of the year — had a problem this protocol does not touch. They did not need
  to know AI was used. They needed the reports to be good.

### What survived

The half nobody attacked: **you can check it yourself, offline, in one file.** Recompute the
diff, compare the hash, resolve the key. That is a property you can verify in an afternoon, not
a promise. Whether anyone needs it is exactly what has not been demonstrated.

### What I am not doing

Not building Level 3. Not sending more cold outreach — the channel visibly burns. Not
presenting this as a solution looking for its first user. It is a finished, frozen artifact at
`v0.2.3` with a written spec, a threat model, three verifier implementations compared on
offline directory inputs with supplied keys, and an honest record of being wrong in public.

A note from October 2026: projects that ask for AI disclosure have mostly settled on a plain
commit trailer (`Assisted-by:` or `Generated-by:`), read by people or a simple check, not signed.
I have not seen one ask for a signed declaration.

If you maintain something and you think the premise is wrong in the *other* direction — that
you do have this problem — that is the one thing worth telling me.
