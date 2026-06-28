Project: SPIFast - High Performance Shallow Packet Inspection using DPDK

Architecture source of truth:

Current:
- docs/SRS.md
- docs/HLD.md
- docs/SDD.md

Previous implementation may not match current architecture.

Before implementing new modules:
- Review existing code
- Keep compatible parts
- Refactor if architecture changed

Rules:
- Follow SDD exactly.
- Do not introduce new architecture without discussion.
- No malloc/free in datapath.
- Preserve zero-copy mbuf ownership model.
- Preserve lcore ownership model.