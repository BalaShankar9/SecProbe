# SecProbe · project guide

A Python toolkit with modular security checks and console, HTML and JSON reporting.

**For:** Developers assessing systems they own or have permission to test.<br>
**Current stage:** Security toolkit · validation required<br>
**Reviewed:** 8 September 2026, from repository files and available GitHub workflow records. This is a source review, not a fresh application test or production certification.

## Start with the evidence

- [secprobe](../secprobe)
- [tests](../tests)
- [pyproject.toml](../pyproject.toml)
- [.github/workflows/ci.yml](../.github/workflows/ci.yml)

## A useful first demo

Run selected checks against an isolated fixture application you control. Show one true finding, one clean control, the supporting evidence and the report output.

## Next release checklist

These are proposed acceptance gates. An unchecked item does not imply its implementation is absent; it means fresh release evidence is still needed.

- [ ] Fix package installation, lint and static-analysis failures reported by the existing workflow.
- [ ] Build a labelled fixture suite and publish false-positive and false-negative measurements per scanner.
- [ ] Replace absolute accuracy or agent-count marketing with a tested capability matrix and an example report.

## What to measure

Precision and recall per scanner on a disclosed fixture suite, with unresolved findings explicitly marked.

Publish the dataset or evaluation method, date range, sample size and limitations with each result. Code size, feature counts and agent counts do not measure product usefulness.

## What a finished showcase contains

Fixture instructions, scanner matrix, reproducible results and a sanitised report.

Keep one dated release record containing the commit, setup steps, required services, checks run, known limitations and rollback instructions. Add screenshots from that version using fictional or consented data; identify demo fixtures clearly.

## Three ways to evaluate this project

| Visitor | Start here | Evidence to look for |
| --- | --- | --- |
| Potential client | The demo scenario above | A repeatable workflow and a measurable outcome |
| Engineering team | Linked source and tests | Design decisions, failure handling and reproducibility |
| Product user or collaborator | README setup and release notes | A supported journey, current limitations and feedback route |

[Repository overview](../README.md) · [Issues](https://github.com/BalaShankar9/SecProbe/issues) · [More projects](https://github.com/BalaShankar9)
