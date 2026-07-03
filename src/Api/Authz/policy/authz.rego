package authz
import future.keywords.if
import future.keywords.in

default permit := false
default deny := false
default allow := false

permit if {
	input.action == "read"
	input.resource.classification <= input.caller.level
}
permit if {
	input.action == "write"
	input.caller.department == input.resource.owner_department
	input.resource.classification <= input.caller.level
}
permit if {
	input.action == "read"
	"incident_responder" in input.caller.roles
	input.context.break_glass
}
deny if {
	input.action == "write"
	input.resource.frozen
}
allow if {
	permit
	not deny
}
decision := {"permit": allow}
