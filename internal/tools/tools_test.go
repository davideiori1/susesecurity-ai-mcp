package tools

import (
	"context"
	"testing"

	"mcp/internal/tools/mocks"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
	v1 "k8s.io/api/core/v1" // Import the core v1 types
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	dynamicfake "k8s.io/client-go/dynamic/fake"
)

const (
	fakeUrl   = "https://localhost:8080"
	fakeToken = "token-xxx"
)

var podGVR = schema.GroupVersionResource{Group: "", Version: "v1", Resource: "pods"}

var reportGVR = schema.GroupVersionResource{
	Group:    "storage.sbomscanner.kubewarden.io",
	Version:  "v1alpha1",
	Resource: "vulnerabilityreports",
}

func scheme() *runtime.Scheme {
	scheme := runtime.NewScheme()
	_ = v1.AddToScheme(scheme)

	return scheme
}

func TestGetVulnerabilityWorkloadSummary(t *testing.T) {
	ctlr := gomock.NewController(t)
	defer ctlr.Finish()

	// 1. Define the SHA we want to match
	const imageSHA = "a1b2c3d4e5f6"
	const fullImageID = "docker-pullable://registry/repo@sha256:" + imageSHA

	// 2. Fake Pod
	fakePod := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "v1",
			"kind":       "Pod",
			"metadata": map[string]interface{}{
				"name":      "cartservice-12345",
				"namespace": "default",
			},
			"status": map[string]interface{}{
				"containerStatuses": []interface{}{
					map[string]interface{}{
						"name":    "server",
						"imageID": fullImageID,
					},
				},
			},
		},
	}

	// 3. Fake Report
	fakeReport := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "storage.sbomscanner.kubewarden.io/v1alpha1",
			"kind":       "VulnerabilityReport",
			"metadata": map[string]interface{}{
				"name":      "report-abcde",
				"namespace": "default",
			},
			"imageMetadata": map[string]interface{}{
				"digest": imageSHA,
			},
			"report": map[string]interface{}{
				"summary": map[string]interface{}{
					"critical": int64(5),
					"high":     int64(10),
					"medium":   int64(3),
					"low":      int64(1),
					"unknown":  int64(0),
				},
			},
		},
	}

	// This tells the fake client: "When someone lists 'vulnerabilityreports',
	// give them a 'VulnerabilityReportList'."
	gvrToListKind := map[schema.GroupVersionResource]string{
		reportGVR: "VulnerabilityReportList",
	}

	tests := map[string]struct {
		params         ResourceParams
		mockClient     func() K8sClient
		expectedResult string
		expectedError  string
	}{
		"success": {
			params: ResourceParams{Name: "cartservice", Namespace: "default", Cluster: "local"},
			mockClient: func() K8sClient {
				mock := mocks.NewMockK8sClient(ctlr)

				// Mock Pod List (Core types work automatically)
				podClient := dynamicfake.NewSimpleDynamicClient(scheme(), fakePod).Resource(podGVR).Namespace("default")
				mock.EXPECT().GetResourceInterface(fakeToken, fakeUrl, "default", "local", podGVR).Return(podClient, nil)

				// Mock Report List (Use WithCustomListKinds)
				reportClient := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(scheme(), gvrToListKind, fakeReport).Resource(reportGVR).Namespace("default")
				mock.EXPECT().GetResourceInterface(fakeToken, fakeUrl, "default", "local", reportGVR).Return(reportClient, nil)

				return mock
			},
			expectedResult: "Security Scan Summary for cartservice:\n- Critical: 5\n- High: 10\n- Medium: 3\n- Low: 1\n- Unknown: 0",
		},
		"no report found": {
			params: ResourceParams{Name: "cartservice", Namespace: "default", Cluster: "local"},
			mockClient: func() K8sClient {
				mock := mocks.NewMockK8sClient(ctlr)

				// Pod Found
				podClient := dynamicfake.NewSimpleDynamicClient(scheme(), fakePod).Resource(podGVR).Namespace("default")
				mock.EXPECT().GetResourceInterface(fakeToken, fakeUrl, "default", "local", podGVR).Return(podClient, nil)

				// Report Missing (Pass NO objects, but STILL pass the ListKind mapping)
				reportClient := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(scheme(), gvrToListKind).Resource(reportGVR).Namespace("default")
				mock.EXPECT().GetResourceInterface(fakeToken, fakeUrl, "default", "local", reportGVR).Return(reportClient, nil)

				return mock
			},
			expectedError: "no vulnerability report found",
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			tools := Tools{client: test.mockClient()}

			req := &mcp.CallToolRequest{
				Extra: &mcp.RequestExtra{Header: map[string][]string{
					urlHeader:   {fakeUrl},
					tokenHeader: {fakeToken},
				}},
			}

			result, _, err := tools.GetVulnerabilityWorkloadSummary(context.TODO(), req, test.params)

			if test.expectedError != "" {
				assert.ErrorContains(t, err, test.expectedError)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, test.expectedResult, result.Content[0].(*mcp.TextContent).Text)
			}
		})
	}
}
