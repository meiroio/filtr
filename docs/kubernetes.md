# Kubernetes deployment

[Back to deployment choices](../README.md)

The public image **`ghcr.io/meiroio/filtr:0.1.2`** supports **linux/amd64 and linux/arm64** under one multi-architecture tag. Nodes pull the appropriate image without registry credentials. Download the deployment manifest without cloning or building the project:

```sh
set -eu
mkdir filtr-kubernetes-v0.1.2
cd filtr-kubernetes-v0.1.2
curl --fail --location \
  https://github.com/meiroio/filtr/releases/download/v0.1.2/filtr-v0.1.2-kubernetes.yaml \
  --output filtr.yaml
```

The manifest already uses the versioned image. `ghcr.io/meiroio/filtr:latest` tracks published stable releases; prefer a version or manifest digest for controlled deployments. To resolve a digest on a machine with Docker, run `docker buildx imagetools inspect ghcr.io/meiroio/filtr:0.1.2`, then set `image: ghcr.io/meiroio/filtr:0.1.2@sha256:THE_INDEX_DIGEST`. Use the top-level multi-architecture digest for a mixed cluster. Source builds remain an optional [development workflow](development.md#docker).

`filtr.yaml` supplies a Deployment, ClusterIP Service and 1 GiB persistent volume claim; its maintained source is [deploy/kubernetes/filtr.yaml](https://github.com/meiroio/filtr/blob/main/deploy/kubernetes/filtr.yaml). It does not create a public load balancer, ingress, certificate or network isolation rules. Edit the Deployment's `env` entry for `FILTR_UPSTREAM` to match your application Service. For example, `http://application.default.svc.cluster.local:3000` means Service `application`, namespace `default`, Service port `3000`. Use your cluster's storage class if it has no default. The examples below use the default namespace. The runtime uses a read-only root filesystem, drops capabilities, runs without root or a service-account token, and writes only to `/data`.

### Connect the existing ingress

In your existing [Ingress](https://kubernetes.io/docs/concepts/services-networking/ingress/), change the backend for the protected hostname/path from your application Service to `filtr` on port `8080`. Keep the current ingress class, hostname, TLS certificate and controller-specific settings. An illustrative configuration is:

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: application
  namespace: default
spec:
  ingressClassName: your-existing-class
  tls:
    - hosts: [app.example.com]
      secretName: your-existing-tls-secret
  rules:
    - host: app.example.com
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: filtr
                port:
                  number: 8080
```

This uses an already installed ingress controller. The Ingress and `filtr` Service must be in the same namespace. If your cluster uses Gateway API or a cloud load balancer directly, change its equivalent backend/target to the Filtr Service. The next hop remains the application Service configured in `FILTR_UPSTREAM`, never the public ingress hostname. Apply the ingress change after installing and checking Filtr's policy. Set exact trusted ingress socket-peer IPs through `FILTR_TRUSTED_PROXIES` when original client/HTTPS metadata is needed; CIDRs and automatic pod-IP tracking are not implemented.

Keep the application Service private and remove alternate public routes to it. A `ClusterIP` Service alone does not restrict other pods. Apply [NetworkPolicies](https://kubernetes.io/docs/concepts/services-networking/network-policies/) appropriate to your namespaces and labels: allow the ingress controller to reach Filtr on 8080 and Filtr to reach the application's HTTP port; restrict direct access to that application port. NetworkPolicy enforcement requires a supporting cluster network plugin. Preserve required DNS, provider egress and operational access. These policies depend on your cluster and are not included in the generic manifest.

### Install secrets, storage and policy

Create the admin Secret from a local protected file without a trailing newline:

```sh
umask 077
mkdir -p .secrets
openssl rand -hex 64 | tr -d '\n' > .secrets/admin-token
kubectl create secret generic filtr-admin \
  --from-file=FILTR_ADMIN_TOKEN=.secrets/admin-token
```

Optionally create `.secrets/ai.env` with the configured provider keys and primary preference, then create the `filtr-ai` Secret. For example, its contents can use these variable names:

```dotenv
ANTHROPIC_API_KEY=your-provider-issued-key
OPENAI_API_KEY=your-provider-issued-key
FILTR_AI_PROVIDER=anthropic
```

```sh
kubectl create secret generic filtr-ai --from-env-file=.secrets/ai.env
kubectl apply -f filtr.yaml
kubectl get pods -l app.kubernetes.io/name=filtr
```

Omit `filtr-ai` for static-only operation. Keep `.secrets/` outside version control; this repository ignores it. Use your organization's secret manager for production delivery. To rotate a Secret used through environment variables, update it and restart the Deployment's pods.

The pod initially runs without becoming Ready because no SBOM is installed. In one terminal, forward the private admin port directly to the Deployment (not the Service):

```sh
kubectl port-forward --address 127.0.0.1 deployment/filtr 9090:9090
```

In another terminal, load the same admin secret and upload the full inventory:

```sh
export FILTR_ADMIN_TOKEN="$(cat .secrets/admin-token)"
printf 'header = "Authorization: Bearer %s"\n' "$FILTR_ADMIN_TOKEN" |
  curl --config - --noproxy '*' --fail-with-body --max-time 960 \
  http://127.0.0.1:9090/v1/sbom \
  -H 'Content-Type: application/json' \
  --data-binary @combined.sbom.cdx.json \
  --output filtr-upload-report.json
kubectl rollout status deployment/filtr --timeout=960s
```

Use the same port-forward and upload command for subsequent releases. [Port forwarding](https://kubernetes.io/docs/tasks/access-application-cluster/port-forward-access-application-cluster/) requires the appropriate operator RBAC permissions. Never add the admin port to a Service or ingress. Route the existing ingress/TLS endpoint to Service `filtr:8080`, and restrict origin access so clients cannot bypass Filtr.

The [authenticated exec probes](https://kubernetes.io/docs/tasks/configure-pod-container/configure-liveness-readiness-startup-probes/) run [deploy/probe.sh](https://github.com/meiroio/filtr/blob/v0.1.2/deploy/probe.sh) inside the pod, keeping the admin token out of curl's arguments. Startup/liveness check admin responsiveness without requiring an SBOM, so first-time installation does not cause restart loops. Readiness checks `/healthz` and succeeds once a policy is installed. It does not assess origin health or promise vulnerability coverage; deliberate quarantine is still a valid ready policy. The startup probe permits 960 seconds with the default AI deadline; increase its budget if you increase those deadlines. Tune resource requests/limits against your own traffic and inventory sizes.

This MVP uses **one replica with a Recreate strategy** and persistent storage so two pods cannot concurrently replace the same policy. Application updates therefore have an interruption. Do not enable an HPA or scale this Deployment without adding policy distribution/coordination; there is no multi-replica control plane. Deploy separate named instances/claims/Secrets for separate upstreams. Persist the entire `/data` directory: restarts reuse cached reviews and research only missing/expired entries using the saved leaderboard, without fetching rankings; a missing or incompatible snapshot uses the existing Luna/static fallback until the next SBOM upload.
