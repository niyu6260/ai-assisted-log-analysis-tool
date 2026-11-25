# Blind-test protocol

Blind tests measure generalization. They must not use a case-specific detector,
root-cause text, expected finding IDs, screenshots containing the answer, or a
previous analyst report before the analyzer output is frozen.

## Intake

For each unknown incident, retain only:

- anonymized log ZIP or directory;
- charger model and serial-number relationships;
- incident start/end time and known timezone;
- customer-observed symptom;
- files that are safe and relevant to ingest.

Keep the expert diagnosis in a separate withheld label file that is not visible
to the analyzer.

## Procedure

1. Assign an opaque ID such as `blind-001`.
2. Record the input metadata without selecting a detector or naming a suspected
   root cause.
3. Run automatic discovery, parsing, correlation, and diagnosis.
4. Freeze `timeline.json`, `findings.json`, `meta.json`, and `report.md`.
5. Reveal the expert label.
6. Score domain identification, root-cause category, conclusion status,
   evidence correctness, unsafe overclaiming, and runtime.
7. Add the case to normal routed regression only after blind scoring is saved.

## Initial batch

Use 5–10 incidents with at least:

- two charging-protocol failures;
- one CP or physical-interface fault;
- one power-conversion or module fault;
- one OCPP/backend business failure;
- one network-path failure;
- one genuinely inconclusive case with missing primary evidence.

Do not tune rules after each individual result. Complete the batch first, group
failure modes, then implement reusable parser or detector capabilities.

## Gate for the automatic-diagnosis phase

The current case runner selects a detector from labeled YAML and therefore is
not blind. Before scoring the first batch, the analyzer must support automatic
detector routing and must prevent detector explanations from reading withheld
ground-truth text.
