# CHANGELOG

## V3.0.0 — National Research Build

### Added

- Structured Extractor provider abstraction
- OpenAI-compatible / Ollama-compatible extraction adapter
- Typed Requirement Graph IR V3
- Formal IR and SMT-LIB2 generation
- Built-in bounded model checker
- Optional Z3 adapter
- Counterexample / witness evidence
- CEGAR repair loop scaffold
- Cross-Agent Leakage detection
- Memory Poisoning detection
- Tool Description Poisoning detection
- Privilege Escalation control
- Unauthorized destructive tool control
- AgentGuard-Bench V3 Candidate 100
- Policy Candidate 50
- Frozen 60/20/20 split and SHA-256 manifest
- Compiler ablation runner
- Runtime ablation runner
- Traceable experiment artifacts
- V3 Research UI for Formal Verification and Benchmark evidence

### Compatibility

- Original API document: 113 HTTP operations
- V3 API: 131 HTTP operations
- Missing original operations: 0

### Verification

- Backend tests: 15 passed
- TypeScript source: type-checked with temporary local declaration stubs because npm registry access was unavailable in the build environment
