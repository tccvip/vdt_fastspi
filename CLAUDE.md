Project: SPIFast - High Performance Shallow Packet Inspection using DPDK

Architecture source of truth:
- docs/SRS.md
- docs/HLD.md
- docs/SDD.md

Rules:
- Follow SDD exactly.
- Do not introduce new architecture without discussion.
- No malloc/free in datapath.
- Preserve zero-copy mbuf ownership model.
- Preserve lcore ownership model.