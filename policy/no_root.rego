# Politique Rego — Interdit l'exécution en tant que root
package main
 
# Règle 1 : refuser si runAsNonRoot n'est pas défini
deny[msg] {
  input.kind == "Deployment"
  container := input.spec.template.spec.containers[_]
  not container.securityContext.runAsNonRoot
  msg := sprintf(
    "ERREUR: Le container '%v' doit avoir runAsNonRoot: true",
    [container.name]
  )
}
 
# Règle 2 : refuser si runAsUser est explicitement 0 (root)
deny[msg] {
  input.kind == "Deployment"
  container := input.spec.template.spec.containers[_]
  container.securityContext.runAsUser == 0
  msg := sprintf(
    "ERREUR: Le container '%v' tourne en tant que root (UID 0) !",
    [container.name]
  )
}
 
# Règle 3 : avertissement si capabilities non limitées
warn[msg] {
  input.kind == "Deployment"
  container := input.spec.template.spec.containers[_]
  not container.securityContext.capabilities.drop
  msg := sprintf(
    "ATTENTION: Le container '%v' n'a pas de capabilities.drop défini",
    [container.name]
  )
}
