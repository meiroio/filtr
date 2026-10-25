"""Profile orchestration; application service and application code stay unchanged."""
from pathlib import Path

import apache
from common import run
import nginx
import node_inventory
import node_runtime


def prepare(args, distro):
    runtime = node_runtime.inspect(args.app_service, args.app_dir, args.backend_port)
    args.backend_port = runtime["backend_port"]
    web_server = args.web_server or "nginx"
    run(["systemctl", "is-active", "--quiet", "nginx" if web_server == "nginx" else "apache2"])
    if web_server == "nginx":
        run(["nginx", "-t"])
        plan = nginx.plan(args.site, args.listen_port, args.backend_port)
    else:
        run(["apache2ctl", "configtest"])
        plan = apache.node_plan(args.site, args.listen_port, args.backend_port)
    sbom, gaps = node_inventory.discover(runtime, distro)
    plan.update(profile="node-express", document_root=runtime["app_dir"], app_service=runtime["app_service"],
                backend_port=runtime["backend_port"], upstream=runtime["upstream"],
                runtime_evidence={"executable": runtime["executable"], "version": runtime["versions"]["node"]})
    return plan, sbom, gaps


def rediscover(metadata, distro):
    runtime = node_runtime.inspect(metadata["app_service"], Path(metadata["document_root"]), metadata["backend_port"])
    if runtime["upstream"] != metadata["upstream"]:
        from common import InstallError
        raise InstallError("Node backend address changed; reconcile routing before refreshing inventory")
    return node_inventory.discover(runtime, distro)
