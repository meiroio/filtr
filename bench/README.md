# Local Docker HTTP benchmark

From a source checkout, with Docker Compose and Python 3:

```sh
python3 bench/run.py --duration 15 --repeats 3 --connections 64 \
  --host-description 'Describe your CPU and RAM' --output data/benchmark
```

Use a new output directory for each run. The harness pulls the published Filtr 0.1.0 image by its multi-architecture manifest digest, builds the existing Rust demo origin and a checksum-verified oha 1.16.0 load-generator image, and creates a separate Compose project. Image builds/downloads require network access; measured HTTP requests remain inside its Docker network. It publishes no host ports, loads no project `.env`, passes no provider keys and removes its own containers/network afterward. Existing application containers are left running. The generated admin secret stays in the benchmark process/container environment and reaches curl through stdin.

Each container has a 2-CPU quota and two runtime workers. Filtr has a 512 MiB memory limit, the origin has 256 MiB and the load generator has 2 GiB for its retained latency samples. Filtr uses its default HTTP limits and baseline guards, with the bundled Log4j 2.14.1 inventory enabling `log4shell-lookups`. This is a small static-policy workload; it does not measure large generated rule sets or paid inventory analysis.

The runner first verifies that the complete 64 KiB body reaches the origin and that AI is unconfigured. It warms each workload for three seconds, then measures three rounds, reversing workload order in alternate rounds:

- Direct origin and Filtr: GET with a small JSON response.
- Direct origin and Filtr: POST with exactly 1 KiB and 64 KiB JSON bodies.
- Filtr: GET with a harmless Log4j lookup marker in `X-Test`, expecting 403.

All traffic uses HTTP/1.1 with persistent connections and no TLS. oha runs a closed-loop workload at the specified concurrency, without a target request rate. These latency samples can therefore understate stalls compared with an independently paced production workload; this is not a latency-SLA or maximum-capacity test. `-w` drains requests at the deadline, and each request has a five-second timeout. Any connection error, unexpected status code or upstream error invalidates the run. A deliberate 403 is the expected result for the blocking case.

The demo origin consumes the full request body and returns a small JSON description. Direct measurements use the same origin and network, without the extra proxy hop. Results include HTTP parsing, request-body inspection, network forwarding and response handling; they exclude TLS, external network latency, real application work and SBOM/AI processing.

`summary.json` reports median requests/second and the medians of each run's p50/p99, plus throughput min/max, response counts, policy counters, source revision, image digest and Docker VM resources. These are per-run quantile medians, not pooled request percentiles. The individual oha JSON files preserve complete status/error distributions and latency results. Warm-up traffic is included in policy counters but excluded from the reported measurements. Keep raw output under ignored `data/`; the checked-in [result summary](results/2026-10-25-arm64.json) contains synthetic benchmark metadata and each measured run's throughput, p50/p99, status counts and errors.

Compare machines only with equivalent CPU quotas, native architecture, request data, concurrency, policy and background load. A shared Docker Desktop development host adds VM and scheduling effects. Use the [README performance section](../README.md#performance) for the measured example, and run the harness on representative infrastructure before choosing capacity or SLA targets.
