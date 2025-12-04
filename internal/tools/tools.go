package tools

import (
	"context"
	"fmt"
	"mcp/internal/tools/converter"
	"mcp/internal/tools/k8s"
	"mcp/internal/tools/response"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"go.uber.org/zap"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
)

const (
	tokenHeader = "R_token"
	urlHeader   = "R_url"
)

// GetParams holds the parameters required to get a resource from k8s.
type GetParams struct {
	Cluster   string // The Cluster ID.
	Kind      string // The Kind of the Kubernetes resource (e.g., "pod", "deployment").
	Namespace string // The Namespace of the resource (optional).
	Name      string // The Name of the resource (optional).
	URL       string // The base URL of the Rancher server.
	Token     string // The authentication Token for Steve.
}

// ListParams holds the parameters required to list resources from k8s.
type ListParams struct {
	Cluster       string // The Cluster ID.
	Kind          string // The Kind of the Kubernetes resource (e.g., "pod", "deployment").
	Namespace     string // The Namespace of the resource (optional).
	Name          string // The Name of the resource (optional).
	URL           string // The base URL of the Rancher server.
	Token         string // The authentication Token for Steve.
	LabelSelector string // Optional LabelSelector string for the request.
}

// ResourceParams uniquely identifies a specific named resource within a cluster.
type ResourceParams struct {
	Name      string `json:"name" jsonschema:"the name of k8s resource"`
	Namespace string `json:"namespace" jsonschema:"the namespace of the resource"`
	Kind      string `json:"kind" jsonschema:"the kind of the resource"`
	Cluster   string `json:"cluster" jsonschema:"the cluster of the resource"`
}

// GetNodesParams specifies the parameters needed to retrieve node metrics.
type GetNodesParams struct {
	Cluster string `json:"cluster" jsonschema:"the cluster of the resource"`
}

type JSONPatch struct {
	Op    string `json:"op"`
	Path  string `json:"path"`
	Value any    `json:"value,omitempty"`
}

// ListKubernetesResourcesParams specifies the parameters needed to list kubernetes resources.
type ListKubernetesResourcesParams struct {
	Namespace string `json:"namespace" jsonschema:"the namespace of the resource"`
	Kind      string `json:"kind" jsonschema:"the kind of the resource"`
	Cluster   string `json:"cluster" jsonschema:"the cluster of the resource"`
}

// SpecificResourceParams uniquely identifies a resource with a known kind within a cluster.
type SpecificResourceParams struct {
	Name      string `json:"name" jsonschema:"the name of k8s resource"`
	Namespace string `json:"namespace" jsonschema:"the namespace of the resource"`
	Cluster   string `json:"cluster" jsonschema:"the cluster of the resource"`
}

type GetClusterImagesParams struct {
	Clusters []string `json:"clusters" jsonschema:"the clusters where images are returned"`
}

// ContainerLogs holds logs for multiple containers.
type ContainerLogs struct {
	Logs map[string]any `json:"logs"`
}

// K8sClient defines an interface for a Kubernetes client.
type K8sClient interface {
	GetResourceInterface(token string, url string, namespace string, cluster string, gvr schema.GroupVersionResource) (dynamic.ResourceInterface, error)
	CreateClientSet(token string, url string, cluster string) (kubernetes.Interface, error)
}

// Tools contains all tools for the MCP server
type Tools struct {
	client K8sClient
}

// NewTools creates and returns a new Tools instance.
func NewTools() *Tools {
	return &Tools{
		client: k8s.NewClient(),
	}
}

// Define the extra filters for the vulnerability reports
type VulnerabilityScanParams struct {
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
	Cluster   string `json:"cluster"`
	Severity  string `json:"severity,omitempty"` // Optional: e.g., "Critical", "High"
	CVE       string `json:"cve_id,omitempty"`   // Optional: e.g., "CVE-2025-1234"
}

type VulnerabilityStatsParams struct {
	Namespace string `json:"namespace,omitempty"` // Optional: If empty, scans whole cluster
	Cluster   string `json:"cluster"`
}

// GetResource retrieves a specific Kubernetes resource based on the provided parameters.
func (t *Tools) GetResource(ctx context.Context, toolReq *mcp.CallToolRequest, params ResourceParams) (*mcp.CallToolResult, any, error) {
	zap.L().Debug("getKubernetesResource called")

	resource, err := t.getResource(ctx, GetParams{
		Cluster:   params.Cluster,
		Kind:      params.Kind,
		Namespace: params.Namespace,
		Name:      params.Name,
		URL:       toolReq.Extra.Header.Get(urlHeader),
		Token:     toolReq.Extra.Header.Get(tokenHeader),
	})
	if err != nil {
		zap.L().Error("failed to get resource", zap.String("tool", "getKubernetesResource"), zap.Error(err))
		return nil, nil, err
	}

	mcpResponse, err := response.CreateMcpResponse([]*unstructured.Unstructured{resource}, params.Cluster)
	if err != nil {
		zap.L().Error("failed to create mcp response", zap.String("tool", "listKubernetesResource"), zap.Error(err))
		return nil, nil, err
	}

	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: mcpResponse}},
	}, nil, nil
}

func (t *Tools) getResource(ctx context.Context, params GetParams) (*unstructured.Unstructured, error) {
	resourceInterface, err := t.client.GetResourceInterface(params.Token, params.URL, params.Namespace, params.Cluster, converter.K8sKindsToGVRs[strings.ToLower(params.Kind)])
	if err != nil {
		return nil, err
	}

	obj, err := resourceInterface.Get(ctx, params.Name, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}

	return obj, err
}

func (t *Tools) getResources(ctx context.Context, params ListParams) ([]*unstructured.Unstructured, error) {
	resourceInterface, err := t.client.GetResourceInterface(params.Token, params.URL, params.Namespace, params.Cluster, converter.K8sKindsToGVRs[strings.ToLower(params.Kind)])
	if err != nil {
		return nil, err
	}

	opts := metav1.ListOptions{}
	if params.LabelSelector != "" {
		opts.LabelSelector = params.LabelSelector
	}
	list, err := resourceInterface.List(ctx, opts)
	if err != nil {
		return nil, err
	}

	objs := make([]*unstructured.Unstructured, len(list.Items))
	for i := range list.Items {
		objs[i] = &list.Items[i]
	}

	return objs, err
}

// GetVulnerabilityWorkloadSummary: Returns the high-level Critical/High/Medium counts
func (t *Tools) GetVulnerabilityWorkloadSummary(ctx context.Context, toolReq *mcp.CallToolRequest, params ResourceParams) (*mcp.CallToolResult, any, error) {
	zap.L().Debug("getVulnerabilityWorkloadSummary called")

	zap.L().Info("calling findReportForWorkload with parameters",
		zap.String("workload_name", params.Name),
		zap.String("namespace", params.Namespace),
		zap.String("cluster", params.Cluster),
	)

	// 1. Find the Vulnerability Report for this workload
	report, err := t.findReportForWorkload(ctx, toolReq, params.Name, params.Namespace, params.Cluster)
	if err != nil {
		zap.L().Error("failed to get vulnerability report", zap.String("tool", "getVulnerabilityWorkloadSummary"), zap.Error(err))
		return nil, nil, err
	}

	// 2. Extract Summary from the CRD JSON path: .report.summary
	summary, found, _ := unstructured.NestedMap(report.Object, "report", "summary")
	if !found {
		err := fmt.Errorf("report found, but summary field is missing")
		zap.L().Error("invalid report structure", zap.String("tool", "getVulnerabilityWorkloadSummary"), zap.Error(err))
		return nil, nil, err
	}

	// 3. Format the text response
	result := fmt.Sprintf(
		"Security Scan Summary for %s:\n- Critical: %v\n- High: %v\n- Medium: %v\n- Low: %v\n- Unknown: %v",
		params.Name,
		summary["critical"],
		summary["high"],
		summary["medium"],
		summary["low"],
		summary["unknown"],
	)

	// return mcp.NewToolResultText(result), nil
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: string(result)}},
	}, nil, nil
}

// GetVulnerabilityList: Returns a filtered list of vulnerabilities
func (t *Tools) GetVulnerabilityList(ctx context.Context, toolReq *mcp.CallToolRequest, params VulnerabilityScanParams) (*mcp.CallToolResult, any, error) {
	zap.L().Info("getVulnerabilityList called",
		zap.String("workload", params.Name),
		zap.String("severity_filter", params.Severity),
		zap.String("cve_filter", params.CVE))

	// 1. Reuse the helper to find the Report
	report, err := t.findReportForWorkload(ctx, toolReq, params.Name, params.Namespace, params.Cluster)
	if err != nil {
		zap.L().Error("failed to get vulnerability report", zap.String("tool", "getVulnerabilityWorkloadSummary"), zap.Error(err))
		return nil, nil, err
	}

	// 2. Extract the "results" list (where the vulnerabilities are stored)
	results, found, _ := unstructured.NestedSlice(report.Object, "report", "results")

	zap.L().Info("Extracted report results",
		zap.Bool("found", found),
		zap.Int("results_count", len(results)),
	)

	if !found {
		err := fmt.Errorf("report found, but results field is missing")
		zap.L().Error("invalid report structure", zap.String("tool", "getVulnerabilityList"), zap.Error(err))
		return nil, nil, err
	}

	var matchedVulns []string
	foundSpecificCVE := false

	// 3. Iterate through all results (OS packages, Language binaries, etc.)
	for _, res := range results {
		resultMap, ok := res.(map[string]interface{})
		if !ok {
			continue
		}

		vulns, found, _ := unstructured.NestedSlice(resultMap, "vulnerabilities")
		if !found {
			continue
		}

		for _, v := range vulns {
			vuln, ok := v.(map[string]interface{})
			if !ok {
				continue
			}

			vulnID, _, _ := unstructured.NestedString(vuln, "cve")       // e.g. CVE-2025-22869
			vulnSev, _, _ := unstructured.NestedString(vuln, "severity") // e.g. HIGH
			pkgName, _, _ := unstructured.NestedString(vuln, "packageName")
			installed, _, _ := unstructured.NestedString(vuln, "installedVersion")
			fixedList, _, _ := unstructured.NestedStringSlice(vuln, "fixedVersions")
			fixed := strings.Join(fixedList, ", ")
			if fixed == "" {
				fixed = "None"
			}

			zap.L().Info("vulnerability found",
				zap.String("vulnerabilityID", vulnID),
				zap.String("severity", vulnSev),
				zap.String("pkgName", pkgName),
				zap.String("installedVersion", installed),
				zap.String("fixedVersions", fixed))

			// FILTER 1: Specific CVE Check
			if params.CVE != "" {
				if strings.EqualFold(vulnID, params.CVE) {
					foundSpecificCVE = true
					matchedVulns = append(matchedVulns, fmt.Sprintf("• FOUND %s (%s) in package %s (Current: %s, Fixed: %s)", vulnID, vulnSev, pkgName, installed, fixed))
				}
				continue // If searching for specific CVE, skip other checks
			}

			// FILTER 2: Severity Check
			if params.Severity != "" {
				if !strings.EqualFold(vulnSev, params.Severity) {
					continue
				}
			}

			// Add to list
			matchedVulns = append(matchedVulns, fmt.Sprintf("| %s | %s | %s | %s |", vulnID, vulnSev, pkgName, fixed))
		}
	}

	// 4. Construct the Final Output
	var response string

	// Case A: User asked "Has CVE-123 been found?"
	if params.CVE != "" {
		if foundSpecificCVE {
			response = fmt.Sprintf("YES. %s was found in workload %s:\n%s", params.CVE, params.Name, strings.Join(matchedVulns, "\n"))
		} else {
			response = fmt.Sprintf("NO. %s was NOT found in workload %s.", params.CVE, params.Name)
		}
	} else {
		// Case B: User asked "List all/high vulnerabilities"
		if len(matchedVulns) > 0 {
			header := fmt.Sprintf("Vulnerabilities for %s (Filter: %s):\n| ID | Severity | Package | Fixed Version |\n|---|---|---|---|\n", params.Name, params.Severity)
			response = header + strings.Join(matchedVulns, "\n")
		} else {
			response = fmt.Sprintf("No vulnerabilities found for %s matching your criteria.", params.Name)
		}
	}

	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: response}},
	}, nil, nil
}

// GetVulnerabilityStats: Unified tool for Namespace AND Cluster-wide scans
func (t *Tools) GetVulnerabilityStats(ctx context.Context, toolReq *mcp.CallToolRequest, params VulnerabilityStatsParams) (*mcp.CallToolResult, any, error) {
	// Log the mode we are running in
	if params.Namespace == "" {
		zap.L().Info("getVulnerabilityStats called (Cluster-Wide)", zap.String("cluster", params.Cluster))
	} else {
		zap.L().Info("getVulnerabilityStats called (Namespace-Scoped)", zap.String("namespace", params.Namespace))
	}

	// 1. Fetch VulnerabilityReports (Batch Fetch)
	// If params.Namespace is "", this helper automatically lists resources from ALL namespaces
	reports, err := t.getResources(ctx, ListParams{
		Cluster:   params.Cluster,
		Kind:      "vulnerabilityreport",
		Namespace: params.Namespace,
		URL:       toolReq.Extra.Header.Get(urlHeader),
		Token:     toolReq.Extra.Header.Get(tokenHeader),
	})
	if err != nil {
		return nil, nil, fmt.Errorf("failed to list reports: %w", err)
	}
	zap.L().Info("fetched vulnerability reports", zap.Int("count", len(reports))) // <--- Log Count

	// 2. Index Reports by Digest for fast O(1) lookup
	// We reuse the exact same field structure as your existing tool: .imageMetadata.digest and .report.summary
	reportIndex := make(map[string]map[string]interface{})
	for _, report := range reports {
		digest, found, _ := unstructured.NestedString(report.Object, "imageMetadata", "digest")
		if !found {
			continue
		}

		cleanDigest := digest
		if idx := strings.LastIndex(digest, "sha256:"); idx != -1 {
			cleanDigest = digest[idx+7:]
		}

		summary, found, _ := unstructured.NestedMap(report.Object, "report", "summary")
		if found {
			reportIndex[cleanDigest] = summary
		}
	}
	zap.L().Info("indexed reports", zap.Int("index_size", len(reportIndex))) // <--- Log Index Size

	// 3. Fetch Pods (Filtered by Namespace if provided, or All if empty)
	pods, err := t.getResources(ctx, ListParams{
		Cluster:   params.Cluster,
		Kind:      "pod",
		Namespace: params.Namespace,
		URL:       toolReq.Extra.Header.Get(urlHeader),
		Token:     toolReq.Extra.Header.Get(tokenHeader),
	})
	if err != nil {
		return nil, nil, fmt.Errorf("failed to list pods: %w", err)
	}
	zap.L().Info("fetched pods", zap.Int("count", len(pods))) // <--- Log Count

	// 4. Aggregate Stats
	type WorkloadStats struct {
		Namespace string
		Critical  int64
		High      int64
		Medium    int64
	}
	// Key = "namespace/workloadName" to ensure uniqueness across namespaces
	workloadVulns := make(map[string]WorkloadStats)
	podsMatched := 0 // Counter for debugging

	for _, pod := range pods {
		ns := pod.GetNamespace()
		labels := pod.GetLabels()

		// Logic to determine the Workload Name (matching your standard approach)
		workloadName := labels["app.kubernetes.io/name"]
		if workloadName == "" {
			workloadName = labels["app"]
		}
		if workloadName == "" {
			workloadName = pod.GetName()
		}

		zap.L().Info("workload found", zap.String("workload name", workloadName))

		key := fmt.Sprintf("%s/%s", ns, workloadName)

		// Skip if already processed (deduplication of replicas)
		if _, exists := workloadVulns[key]; exists {
			continue
		}

		// Match Container Images to Reports
		statuses, found, _ := unstructured.NestedSlice(pod.Object, "status", "containerStatuses")
		if !found {
			continue
		}

		for _, s := range statuses {
			status, ok := s.(map[string]interface{})
			if !ok {
				continue
			}

			imageID, _, _ := unstructured.NestedString(status, "imageID")
			// Extract SHA: "docker-pullable://...@sha256:<hash>" -> "<hash>"
			if idx := strings.LastIndex(imageID, "sha256:"); idx != -1 {
				sha := imageID[idx+7:]

				if summary, exists := reportIndex[sha]; exists {

					podsMatched++

					stats := workloadVulns[key]
					stats.Namespace = ns

					// Reuse the same field extraction logic as GetVulnerabilityWorkloadSummary
					crit, _ := summary["critical"].(int64)
					high, _ := summary["high"].(int64)
					med, _ := summary["medium"].(int64)

					stats.Critical += crit
					stats.High += high
					stats.Medium += med

					workloadVulns[key] = stats
				} else {
					// Useful log: Pod found, but no scan report yet
					zap.L().Debug("no report found for image", zap.String("pod", pod.GetName()), zap.String("sha", sha))
				}
			}
		}
	}

	zap.L().Info("aggregation complete",
		zap.Int("matched_pods", podsMatched),
		zap.Int("unique_workloads", len(workloadVulns))) // <--- Final Stat Log

	// 5. Build Output Table
	var sb strings.Builder
	title := fmt.Sprintf("Vulnerability Stats for Namespace '%s'", params.Namespace)
	if params.Namespace == "" {
		title = "Cluster-Wide Vulnerability Stats"
	}

	sb.WriteString(fmt.Sprintf("%s:\n", title))
	// We ALWAYS include the Namespace column for consistency
	sb.WriteString("| Namespace | Workload | Critical | High | Medium |\n")
	sb.WriteString("|---|---|---|---|---|\n")

	if len(workloadVulns) == 0 {
		zap.L().Error("No vulnerable workloads found.", zap.String("tool", "getVulnerabilityStats"))
		return nil, nil, err
	}

	for name, stats := range workloadVulns {
		// name key is "ns/workload", split to get clear name
		parts := strings.Split(name, "/")
		shortName := parts[1]

		// Only show affected workloads
		if stats.Critical > 0 || stats.High > 0 || stats.Medium > 0 {
			sb.WriteString(fmt.Sprintf("| %s | %s | %d | %d | %d |\n", stats.Namespace, shortName, stats.Critical, stats.High, stats.Medium))
		}
	}

	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: sb.String()}},
	}, nil, nil
}

// --- Helper: Find the Report by matching Pod Image ---
func (t *Tools) findReportForWorkload(ctx context.Context, req *mcp.CallToolRequest, workload, namespace, cluster string) (*unstructured.Unstructured, error) {
	// A. Get the Pods for this workload to find the running image SHA
	// We reuse your existing 'ListKubernetesResources' logic indirectly by calling getResources
	pods, err := t.getResources(ctx, ListParams{
		Cluster:   cluster,
		Kind:      "pod",
		Namespace: namespace,
		URL:       req.Extra.Header.Get(urlHeader),
		Token:     req.Extra.Header.Get(tokenHeader),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to list pods: %w", err)
	}

	var targetImageDigest string

	// Find a pod that matches the workload name
	for _, pod := range pods {
		if strings.HasPrefix(pod.GetName(), workload) {

			// IMPROVEMENT: Check ALL containers, not just the first one [0].
			// This handles sidecars (Istio) or InitContainers.
			statuses, found, _ := unstructured.NestedSlice(pod.Object, "status", "containerStatuses")
			if found {
				for _, s := range statuses {
					status := s.(map[string]interface{})

					// Option: If you want to be very specific, check if status["name"] == workload
					// For now, we just grab the first valid SHA we find, which is safer than hardcoding [0]
					imageID, _, _ := unstructured.NestedString(status, "imageID")

					if strings.Contains(imageID, "sha256:") {
						if idx := strings.LastIndex(imageID, "sha256:"); idx != -1 {
							targetImageDigest = imageID[idx+7:] // Extract just the hash part
							break                               // Found a valid SHA, break the inner loop
						}
					}
				}
			}
		}
		if targetImageDigest != "" {
			break // Found our target pod, break the outer loop
		}
	}

	if targetImageDigest == "" {
		return nil, fmt.Errorf("could not determine running image SHA for workload %s", workload)
	}

	zap.L().Info("Looking for report matching digest", zap.String("digest", targetImageDigest))

	// B. List all VulnerabilityReports
	// NOTE: Ensure "vulnerabilityreport" is added to internal/tools/converter/grv.go!
	reports, err := t.getResources(ctx, ListParams{
		Cluster:   cluster,
		Kind:      "vulnerabilityreport",
		Namespace: namespace,
		URL:       req.Extra.Header.Get(urlHeader),
		Token:     req.Extra.Header.Get(tokenHeader),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to list vulnerability reports: %w", err)
	}

	// C. Find the report that matches our digest
	// Based on your CRD file, the digest is at the root: .imageMetadata.digest
	for _, report := range reports {
		digest, found, _ := unstructured.NestedString(report.Object, "imageMetadata", "digest")
		if found && strings.Contains(digest, targetImageDigest) {
			return report, nil
		}
	}

	return nil, fmt.Errorf("no vulnerability report found for image digest %s", targetImageDigest)
}
