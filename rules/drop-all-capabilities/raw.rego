package armo_builtins

import future.keywords.in

# Fails if pod does not drop all capabilities 
deny[msga] {
	wl := input[_]
	wl.kind == "Pod"
	path_to_containers := ["spec", "containers"]
	containers := object.get(wl, path_to_containers, [])
	container := containers[i]

	fixPaths := container_doesnt_drop_ALL(container, i, path_to_containers)

	msga := {
		"alertMessage": sprintf("Pod: %s does not drop all capabilities", [wl.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"failedPaths": [],
		"fixPaths": fixPaths,
		"alertObject": {"k8sApiObjects": [wl]},
	}
}

# Fails if workload does not drop all capabilities
deny[msga] {
	wl := input[_]
	spec_template_spec_patterns := {"Deployment", "ReplicaSet", "DaemonSet", "StatefulSet", "Job"}
	spec_template_spec_patterns[wl.kind]
	path_to_containers := ["spec", "template", "spec", "containers"]
	containers := object.get(wl, path_to_containers, [])
	container := containers[i]

	fixPaths := container_doesnt_drop_ALL(container, i, path_to_containers)

	msga := {
		"alertMessage": sprintf("Workload: %v does not drop all capabilities", [wl.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"failedPaths": [],
		"fixPaths": fixPaths,
		"alertObject": {"k8sApiObjects": [wl]},
	}
}

# Fails if CronJob does not drop all capabilities
deny[msga] {
	wl := input[_]
	wl.kind == "CronJob"
	path_to_containers := ["spec", "jobTemplate", "spec", "template", "spec", "containers"]
	containers := object.get(wl, path_to_containers, [])
	container := containers[i]

	fixPaths := container_doesnt_drop_ALL(container, i, path_to_containers)

	msga := {
		"alertMessage": sprintf("Cronjob: %v does not drop all capabilities", [wl.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"failedPaths": [],
		"fixPaths": fixPaths,
		"alertObject": {"k8sApiObjects": [wl]},
	}
}

# Checks if workload does not drop all capabilities
container_doesnt_drop_ALL(container, i, path_to_containers) = fix_path{
	path_to_drop := ["securityContext", "capabilities", "drop"]
	drop_list := object.get(container, path_to_drop, [])
	not all_in_list(drop_list)
	path := sprintf("%s[%d].%s[%d]", [concat(".", path_to_containers), i, concat(".", path_to_drop), count(drop_list)])
	fix_path := [{"path": path, "value": "ALL"}]
}

all_in_list(list) {
	"all" in list
}

all_in_list(list) {
	"ALL" in list
}
