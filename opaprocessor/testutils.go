package opaprocessor

import (
	"encoding/json"
	"fmt"
	"os"
	"reflect"

	"github.com/armosec/opa-utils/reporthandling"
	"gopkg.in/yaml.v2"
)

var relevantFields = []string{"AlertMessage", "FailedPaths", "RuleStatus", "AlertObject"}

// AlertMessage string                            `json:"alertMessage"`
// 	FailedPaths  []string                          `json:"failedPaths"`
// 	RuleStatus   string                            `json:"ruleStatus"`
// 	PackageName  string                            `json:"packagename"`
// 	AlertScore   AlertScore                        `json:"alertScore"`
// 	AlertObject  AlertObject                       `json:"alertObject"`
// 	Context      []string                          `json:"context,omitempty"`  // TODO - Remove
// 	Rulename     string                            `json:"rulename,omitempty"` // TODO - Remove
// 	Exception    *armotypes.PostureExceptionPolicy `json:"exception,omitempty"`

func GetMocks(mocks []string) ([]map[string]interface{}, error) {
	resource := make(map[string]interface{})
	var resources []map[string]interface{}
	for _, mock := range mocks {
		mock, err := GetMockContentFromFile(mock)
		if err != nil {
			return nil, err
		}
		err = json.Unmarshal([]byte(mock), &resource)
		if err != nil {
			return nil, err
		}
		resources = append(resources, resource)
	}
	return resources, nil
}

func convertYamlToJson(i interface{}) interface{} {
	switch x := i.(type) {
	case map[interface{}]interface{}:
		m2 := map[string]interface{}{}
		for k, v := range x {
			if s, ok := k.(string); ok {
				m2[s] = convertYamlToJson(v)
			}
		}
		return m2
	case []interface{}:
		for i, v := range x {
			x[i] = convertYamlToJson(v)
		}
	}
	return i
}

func GetMockContentFromFile(mock string) (string, error) {
	currentDirectoryOfTest, err := os.Getwd()
	if err != nil {
		return "", err
	}
	mockContent, err := os.ReadFile(fmt.Sprintf("%v/%v", currentDirectoryOfTest, mock))
	if err != nil {
		return "", err
	}
	var body interface{}
	if err := yaml.Unmarshal([]byte(mockContent), &body); err != nil {
		return "", err
	}
	body = convertYamlToJson(body)

	mockContentJson, err := json.Marshal(body)
	if err != nil {
		return "", err
	}
	return string(mockContentJson), err
}

func AssertResponses(responses []reporthandling.RuleResponse, expectedResponses []reporthandling.RuleResponse) bool {
	// expectedResponsesMap := make(map[string]interface{})
	// for _,r := range expectedResponses {
	// 	key := fmt.Sprintf("", r.AlertMessage)
	// 	expectedResponsesMap[r] = r
	// }

	return reflect.DeepEqual(responses, expectedResponses)
}