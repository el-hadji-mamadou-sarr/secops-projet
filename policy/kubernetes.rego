package main

# ─────────────────────────────────────────────────────────────
# Rule: Deny pods running as root (runAsUser == 0)
# ─────────────────────────────────────────────────────────────
deny[msg] {
  input.kind == "Deployment"
  container := input.spec.template.spec.containers[_]
  container.securityContext.runAsUser == 0
  msg := sprintf("DENY: container '%v' runs as root (runAsUser=0). Use a non-root UID.", [container.name])
}

deny[msg] {
  input.kind == "Deployment"
  input.spec.template.spec.securityContext.runAsUser == 0
  msg := "DENY: pod-level securityContext sets runAsUser=0 (root). Use a non-root UID."
}

# ─────────────────────────────────────────────────────────────
# Rule: Deny pods that do NOT set runAsNonRoot: true
# ─────────────────────────────────────────────────────────────
deny[msg] {
  input.kind == "Deployment"
  not input.spec.template.spec.securityContext.runAsNonRoot
  msg := "DENY: pod-level securityContext does not set runAsNonRoot: true."
}

# ─────────────────────────────────────────────────────────────
# Rule: Deny privilege escalation
# ─────────────────────────────────────────────────────────────
deny[msg] {
  input.kind == "Deployment"
  container := input.spec.template.spec.containers[_]
  container.securityContext.allowPrivilegeEscalation != false
  msg := sprintf("DENY: container '%v' does not set allowPrivilegeEscalation: false.", [container.name])
}

# ─────────────────────────────────────────────────────────────
# Rule: Require resource limits
# ─────────────────────────────────────────────────────────────
deny[msg] {
  input.kind == "Deployment"
  container := input.spec.template.spec.containers[_]
  not container.resources.limits
  msg := sprintf("DENY: container '%v' has no resource limits defined.", [container.name])
}
