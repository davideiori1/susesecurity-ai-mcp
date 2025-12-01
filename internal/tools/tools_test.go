package tools

import (
	"context"
	"errors"
	"testing"

	"mcp/internal/tools/mocks"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/api/core/v1" // Import the core v1 types
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	dynamicfake "k8s.io/client-go/dynamic/fake"
)

const (
	fakeUrl       = "https://localhost:8080"
	fakeToken     = "token-xxx"
	fakeNamespace = "default"
	fakeCluster   = "c-xfhrf"
)

var fakePod = &corev1.Pod{
	ObjectMeta: metav1.ObjectMeta{
		Name:      "rancher",
		Namespace: "default",
	},
	Spec: corev1.PodSpec{
		Containers: []corev1.Container{
			{
				Name:  "rancher-container",
				Image: "rancher:latest",
			},
		},
	},
}

var podGVR = schema.GroupVersionResource{Group: "", Version: "v1", Resource: "pods"}

var reportGVR = schema.GroupVersionResource{
	Group:    "storage.sbomscanner.kubewarden.io",
	Version:  "v1alpha1",
	Resource: "vulnerabilityreports",
}

func podUnstructured() *unstructured.Unstructured {
	return &unstructured.Unstructured{Object: map[string]interface{}{
		"apiVersion": "v1",
		"kind":       "Pod",
		"metadata": map[string]interface{}{
			"name": "rancher",
		},
		"spec": map[string]interface{}{
			"containers": []interface{}{
				map[string]interface{}{
					"name":  "rancher-container",
					"image": "rancher:latest",
				},
			},
		},
	}}
}

func scheme() *runtime.Scheme {
	scheme := runtime.NewScheme()
	_ = v1.AddToScheme(scheme)

	return scheme
}

func TestGetKubernetesResource(t *testing.T) {
	ctlr := gomock.NewController(t)
	tests := map[string]struct {
		params         ResourceParams
		mockClient     func() K8sClient
		expectedResult string
		expectedError  string
	}{
		"get pod": {
			params: ResourceParams{Name: "rancher", Kind: "pod", Namespace: fakeNamespace, Cluster: fakeCluster},
			mockClient: func() K8sClient {
				mock := mocks.NewMockK8sClient(ctlr)
				fakeClient := dynamicfake.NewSimpleDynamicClient(scheme(), fakePod).Resource(podGVR).Namespace(fakeNamespace)
				mock.EXPECT().GetResourceInterface(fakeToken, fakeUrl, fakeNamespace, fakeCluster, podGVR).Return(fakeClient, nil)

				return mock
			},
			expectedResult: `{"llm":[{"apiVersion":"v1","kind":"Pod","metadata":{"name":"rancher","namespace":"default"},"spec":{"containers":[{"image":"rancher:latest","name":"rancher-container","resources":{}}]},"status":{}}],"uiContext":[{"namespace":"default","kind":"Pod","cluster":"c-xfhrf","name":"rancher","type":"pod"}]}`,
		},
		"get pod - not found": {
			params: ResourceParams{Name: "rancher", Kind: "pod", Namespace: fakeNamespace, Cluster: fakeCluster},
			mockClient: func() K8sClient {
				mock := mocks.NewMockK8sClient(ctlr)
				fakeClient := dynamicfake.NewSimpleDynamicClient(scheme()).Resource(podGVR).Namespace(fakeNamespace)
				mock.EXPECT().GetResourceInterface(fakeToken, fakeUrl, fakeNamespace, fakeCluster, podGVR).Return(fakeClient, nil)

				return mock
			},
			expectedError: `"rancher" not found`,
		},
		"error getting resource interface": {
			params: ResourceParams{Name: "rancher", Kind: "pod", Namespace: fakeNamespace, Cluster: fakeCluster},
			mockClient: func() K8sClient {
				mock := mocks.NewMockK8sClient(ctlr)
				mock.EXPECT().GetResourceInterface(fakeToken, fakeUrl, fakeNamespace, fakeCluster, podGVR).Return(nil, errors.New("unexpected err"))

				return mock
			},
			expectedError: `unexpected err`,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {

			tools := Tools{client: test.mockClient()}

			result, _, err := tools.GetResource(context.TODO(), &mcp.CallToolRequest{
				Extra: &mcp.RequestExtra{Header: map[string][]string{urlHeader: {fakeUrl}, tokenHeader: {fakeToken}}},
			}, test.params)

			if test.expectedError != "" {
				assert.ErrorContains(t, err, test.expectedError)
			} else {
				assert.NoError(t, err)
				assert.JSONEq(t, test.expectedResult, result.Content[0].(*mcp.TextContent).Text)
			}
		})
	}
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

	// --- FIX: Define the List Kind Mapping ---
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

// TODO update all tests to use fake client
/*func TestListKubernetesResource(t *testing.T) {
	ctlr := gomock.NewController(t)

	tests := map[string]struct {
		params         ListKubernetesResourcesParams
		mockClient     func() K8sClient
		expectedResult string
		expectedError  string
	}{
		"get pod list": {
			params: ListKubernetesResourcesParams{Kind: "pod", Namespace: "default", Cluster: "local"},
			mockClient: func() K8sClient {
				mock := mocks.NewMockK8sClient(ctlr)
				mock.EXPECT().GetResources(context.TODO(), k8s.ListParams{
					Cluster:   "local",
					Kind:      "pod",
					Namespace: "default",
					URL:       fakeUrl,
					Token:     fakeToken,
				}).Return([]*unstructured.Unstructured{podUnstructured(), podUnstructured()}, nil)

				return mock
			},
			expectedResult: `{"llm":"[{\"apiVersion\":\"v1\",\"kind\":\"Pod\",\"metadata\":{\"name\":\"rancher\"},\"spec\":{\"containers\":[{\"image\":\"rancher:latest\",\"name\":\"rancher-container\"}]}},{\"apiVersion\":\"v1\",\"kind\":\"Pod\",\"metadata\":{\"name\":\"rancher\"},\"spec\":{\"containers\":[{\"image\":\"rancher:latest\",\"name\":\"rancher-container\"}]}}]","uiContext":[{"namespace":"default","kind":"Pod","cluster":"local","name":"rancher","type":"pod"},{"namespace":"default","kind":"Pod","cluster":"local","name":"rancher","type":"pod"}]}`,
		},
		"error fetching pod list": {
			params: ListKubernetesResourcesParams{Kind: "pod", Namespace: "default", Cluster: "local"},
			mockClient: func() K8sClient {
				mock := mocks.NewMockK8sClient(ctlr)
				mock.EXPECT().GetResources(context.TODO(), k8s.ListParams{
					Cluster:   "local",
					Kind:      "pod",
					Namespace: "default",
					URL:       fakeUrl,
					Token:     fakeToken,
				}).Return(nil, fmt.Errorf("unexpected error"))

				return mock
			},
			expectedError: "unexpected error",
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {

			tools := Tools{client: test.mockClient()}

			result, _, err := tools.ListKubernetesResources(context.TODO(), &mcp.CallToolRequest{
				Extra: &mcp.RequestExtra{Header: map[string][]string{urlHeader: {fakeUrl}, tokenHeader: {fakeToken}}},
			}, test.params)

			if test.expectedError != "" {
				assert.ErrorContains(t, err, test.expectedError)
			} else {
				assert.NoError(t, err)
				assert.JSONEq(t, test.expectedResult, result.Content[0].(*mcp.TextContent).Text)
			}
		})
	}
}

func TestUpdateKubernetesResource(t *testing.T) {
	ctlr := gomock.NewController(t)
	patchData := []interface{}{
		map[string]interface{}{
			"op":    "replace",
			"path":  "/metadata/labels/foo",
			"value": "bar",
		},
	}

	tests := map[string]struct {
		params         UpdateKubernetesResourceParams
		mockClient     func() K8sClient
		expectedResult string
		expectedError  string
	}{
		"patch pod": {
			params: UpdateKubernetesResourceParams{Name: "rancher", Kind: "pod", Namespace: "default", Cluster: "local", Patch: patchData},
			mockClient: func() K8sClient {
				mockResourceInterface := mocks.NewMockResourceInterface(ctlr)
				patchBytes, _ := json.Marshal(patchData)
				mockResourceInterface.EXPECT().Patch(context.TODO(), "rancher", types.JSONPatchType, patchBytes, metav1.PatchOptions{}).Return(podUnstructured(), nil)

				mockClient := mocks.NewMockK8sClient(ctlr)
				mockClient.EXPECT().GetResourceInterface(fakeToken, fakeUrl, "default", "local", converter.K8sKindsToGVRs[strings.ToLower("pod")]).Return(mockResourceInterface, nil)

				return mockClient
			},
			expectedResult: `{"llm":"[{\"apiVersion\":\"v1\",\"kind\":\"Pod\",\"metadata\":{\"name\":\"rancher\"},\"spec\":{\"containers\":[{\"image\":\"rancher:latest\",\"name\":\"rancher-container\"}]}}]","uiContext":[{"namespace":"default","kind":"Pod","cluster":"local","name":"rancher","type":"pod"}]}`,
		},
		"error patching pod": {
			params: UpdateKubernetesResourceParams{Name: "rancher", Kind: "pod", Namespace: "default", Cluster: "local", Patch: patchData},
			mockClient: func() K8sClient {
				mockResourceInterface := mocks.NewMockResourceInterface(ctlr)
				patchBytes, _ := json.Marshal(patchData)
				mockResourceInterface.EXPECT().Patch(context.TODO(), "rancher", types.JSONPatchType, patchBytes, metav1.PatchOptions{}).Return(nil, fmt.Errorf("unexpected error"))

				mockClientCreator := mocks.NewMockK8sClient(ctlr)
				mockClientCreator.EXPECT().GetResourceInterface(fakeToken, fakeUrl, "default", "local", converter.K8sKindsToGVRs[strings.ToLower("pod")]).Return(mockResourceInterface, nil)

				return mockClientCreator
			},
			expectedError: "unexpected error",
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {

			tools := Tools{client: test.mockClient()}

			result, _, err := tools.UpdateKubernetesResource(context.TODO(), &mcp.CallToolRequest{
				Extra: &mcp.RequestExtra{Header: map[string][]string{urlHeader: {fakeUrl}, tokenHeader: {fakeToken}}},
			}, test.params)

			if test.expectedError != "" {
				assert.ErrorContains(t, err, test.expectedError)
			} else {
				assert.NoError(t, err)
				assert.JSONEq(t, test.expectedResult, result.Content[0].(*mcp.TextContent).Text)
			}
		})
	}
}

func TestCreateKubernetesResource(t *testing.T) {
	ctlr := gomock.NewController(t)

	tests := map[string]struct {
		params         CreateKubernetesResourceParams
		mockClient     func() K8sClient
		expectedResult string
		expectedError  string
	}{
		"create pod": {
			params: CreateKubernetesResourceParams{
				Name:      "rancher",
				Kind:      "pod",
				Namespace: "default",
				Cluster:   "local",
				Resource: map[string]interface{}{
					"apiVersion": "v1",
					"kind":       "Pod",
					"metadata": map[string]interface{}{
						"name": "rancher",
					},
					"spec": map[string]interface{}{
						"containers": []interface{}{
							map[string]interface{}{
								"image": "rancher:latest",
								"name":  "rancher-container",
							},
						},
					},
				},
			},
			mockClient: func() K8sClient {
				mockResourceInterface := mocks.NewMockResourceInterface(ctlr)
				mockResourceInterface.EXPECT().Create(context.TODO(), podUnstructured(), metav1.CreateOptions{}).Return(podUnstructured(), nil)

				mockClientCreator := mocks.NewMockK8sClient(ctlr)
				mockClientCreator.EXPECT().GetResourceInterface(fakeToken, fakeUrl, "default", "local", converter.K8sKindsToGVRs[strings.ToLower("pod")]).Return(mockResourceInterface, nil)

				return mockClientCreator
			},

			expectedResult: `{"llm":"[{\"apiVersion\":\"v1\",\"kind\":\"Pod\",\"metadata\":{\"name\":\"rancher\"},\"spec\":{\"containers\":[{\"image\":\"rancher:latest\",\"name\":\"rancher-container\"}]}}]","uiContext":[{"namespace":"default","kind":"Pod","cluster":"local","name":"rancher","type":"pod"}]}`,
		},
		"error creating pod": {
			params: CreateKubernetesResourceParams{
				Name:      "rancher",
				Kind:      "pod",
				Namespace: "default",
				Cluster:   "local",
				Resource: map[string]interface{}{
					"apiVersion": "v1",
					"kind":       "Pod",
					"metadata": map[string]interface{}{
						"name": "rancher",
					},
					"spec": map[string]interface{}{
						"containers": []interface{}{
							map[string]interface{}{
								"image": "rancher:latest",
								"name":  "rancher-container",
							},
						},
					},
				},
			},
			mockClient: func() K8sClient {
				mockClient := mocks.NewMockK8sClient(ctlr)
				mockClient.EXPECT().GetResourceInterface(fakeToken, fakeUrl, "default", "local", converter.K8sKindsToGVRs[strings.ToLower("pod")]).Return(nil, fmt.Errorf("unexpected error"))

				return mockClient
			},
			expectedError: "unexpected error",
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {

			tools := Tools{client: test.mockClient()}

			result, _, err := tools.CreateKubernetesResource(context.TODO(), &mcp.CallToolRequest{
				Extra: &mcp.RequestExtra{Header: map[string][]string{urlHeader: {fakeUrl}, tokenHeader: {fakeToken}}},
			}, test.params)

			if test.expectedError != "" {
				assert.ErrorContains(t, err, test.expectedError)
			} else {
				assert.NoError(t, err)
				assert.JSONEq(t, test.expectedResult, result.Content[0].(*mcp.TextContent).Text)
			}
		})
	}
}

func TestInspectPod(t *testing.T) {
	ctlr := gomock.NewController(t)

	tests := map[string]struct {
		params         SpecificResourceParams
		mockClient     func() K8sClient
		expectedResult string
		expectedError  string
	}{
		"inspect pod": {
			params: SpecificResourceParams{
				Name:      "rancher",
				Namespace: "default",
				Cluster:   "local",
			},
			mockClient: func() K8sClient {
				mock := mocks.NewMockK8sClient(ctlr)
				pod := &corev1.Pod{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "rancher",
						Namespace: "default",
					},
				}
				mock.EXPECT().CreateClientSet(fakeToken, fakeUrl, "local").Return(fake.NewClientset(pod), nil)
				mock.EXPECT().GetResource(context.TODO(), k8s.GetParams{
					Cluster:   "local",
					Kind:      "pod",
					Namespace: "default",
					Name:      "rancher",
					URL:       fakeUrl,
					Token:     fakeToken,
				}).Return(&unstructured.Unstructured{Object: map[string]interface{}{
					"apiVersion": "v1",
					"kind":       "Pod",
					"metadata": map[string]interface{}{
						"name": "rancher",
						"ownerReferences": []interface{}{
							map[string]interface{}{
								"apiVersion": "apps/v1",
								"kind":       "ReplicaSet",
								"name":       "my-replicaset",
								"uid":        "uid",
							},
						},
					},
					"spec": map[string]interface{}{
						"containers": []interface{}{
							map[string]interface{}{
								"name":  "rancher-container",
								"image": "rancher:latest",
							},
						},
					},
				}}, nil)
				mock.EXPECT().GetResource(context.TODO(), k8s.GetParams{
					Cluster:   "local",
					Kind:      "replicaset",
					Namespace: "default",
					Name:      "my-replicaset",
					URL:       fakeUrl,
					Token:     fakeToken,
				}).Return(&unstructured.Unstructured{Object: map[string]interface{}{
					"apiVersion": "apps/v1",
					"kind":       "ReplicaSet",
					"metadata": map[string]interface{}{
						"name": "rancher",
						"ownerReferences": []interface{}{
							map[string]interface{}{
								"apiVersion": "apps/v1",
								"kind":       "Deployment",
								"name":       "my-deployment",
								"uid":        "uid",
							},
						},
					},
				}}, nil)
				mock.EXPECT().GetResource(context.TODO(), k8s.GetParams{
					Cluster:   "local",
					Kind:      "Deployment",
					Namespace: "default",
					Name:      "my-deployment",
					URL:       fakeUrl,
					Token:     fakeToken,
				}).Return(&unstructured.Unstructured{Object: map[string]interface{}{
					"apiVersion": "v1",
					"kind":       "Deployment",
					"metadata": map[string]interface{}{
						"name": "rancher",
					},
				}}, nil)
				mock.EXPECT().GetResource(context.TODO(), k8s.GetParams{
					Cluster:   "local",
					Kind:      "pod.metrics.k8s.io",
					Namespace: "default",
					Name:      "rancher",
					URL:       fakeUrl,
					Token:     fakeToken,
				}).Return(&unstructured.Unstructured{Object: map[string]interface{}{
					"apiVersion": "v1",
					"kind":       "PodMetrics",
					"metadata": map[string]interface{}{
						"name": "rancher",
					},
				}}, nil)
				return mock
			},

			expectedResult: `{"llm":"[{\"apiVersion\":\"v1\",\"kind\":\"Pod\",\"metadata\":{\"name\":\"rancher\",\"ownerReferences\":[{\"apiVersion\":\"apps/v1\",\"kind\":\"ReplicaSet\",\"name\":\"my-replicaset\",\"uid\":\"uid\"}]},\"spec\":{\"containers\":[{\"image\":\"rancher:latest\",\"name\":\"rancher-container\"}]}},{\"apiVersion\":\"v1\",\"kind\":\"Deployment\",\"metadata\":{\"name\":\"rancher\"}},{\"apiVersion\":\"v1\",\"kind\":\"PodMetrics\",\"metadata\":{\"name\":\"rancher\"}},{\"pod-logs\":{\"rancher-container\":\"fake logs\"}}]","uiContext":[{"namespace":"default","kind":"Pod","cluster":"local","name":"rancher","type":"pod"},{"namespace":"default","kind":"Deployment","cluster":"local","name":"rancher","type":"apps.deployment"},{"namespace":"default","kind":"PodMetrics","cluster":"local","name":"rancher","type":"podmetrics"},{"namespace":"default","kind":"","cluster":"local","name":""}]}`,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {

			tools := Tools{
				client: test.mockClient(),
			}

			result, _, err := tools.InspectPod(context.TODO(), &mcp.CallToolRequest{
				Extra: &mcp.RequestExtra{Header: map[string][]string{urlHeader: {fakeUrl}, tokenHeader: {fakeToken}}},
			}, test.params)

			if test.expectedError != "" {
				assert.ErrorContains(t, err, test.expectedError)
			} else {
				assert.NoError(t, err)
				assert.JSONEq(t, test.expectedResult, result.Content[0].(*mcp.TextContent).Text)
			}
		})
	}
}
*/
