# Pull request

## Type
<!-- Pick one. -->
- [ ] New technique mapping
- [ ] New vendor detection on existing technique
- [ ] Mapping correction (data components, references, query)
- [ ] Schema change
- [ ] SPA / tooling change
- [ ] Other

## Linked issue
<!-- "Closes #123" if this PR was generated from an issue form. -->

## Summary
<!-- One paragraph. What changed and why. -->

## Data Component anchoring
<!-- Required for any change touching data/techniques/*.json. -->
- [ ] Every new or modified `vendor_detections[]` block declares at least one entry in `mapped_data_components`.
- [ ] Every name in `mapped_data_components` matches an entry in the same record's `data_components[]`.
- [ ] Every new or modified `data_components[]` entry has a `data_source_id` (DS####) and `data_source_name`.

## Schema validation
- [ ] `pnpm validate` passes locally, or CI passes (the `validate` job is required for merge).

## References
- [ ] Every URL in `references[]` is reachable and authoritative (MITRE, MS, vendor docs, primary sources).
- [ ] Confidence on every detection is set deliberately (`low` / `medium` / `high`) and the `false_positive_considerations` and `limitations` fields are filled where they apply.

## Reviewer notes
<!-- Anything a reviewer should know that is not obvious from the diff. -->
