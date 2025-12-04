package main

import (
	"context"
	"crypto/tls"
	"log"
	"net/http"
	"os"
	"strings"

	"mcp/internal/tools"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/rancher/dynamiclistener"
	"github.com/rancher/dynamiclistener/server"
	"github.com/rancher/wrangler/pkg/generated/controllers/core"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"k8s.io/client-go/rest"
)

const (
	skipTLSVerifyEnvVar = "INSECURE_SKIP_TLS"
	tlsName             = "rancher-mcp-server.cattle-ai-agent-system.svc"
	certNamespace       = "cattle-ai-agent-system"
	certName            = "cattle-mcp-tls"
	caName              = "cattle-mcp-ca"
)

func init() {
	if strings.ToLower(os.Getenv("LOG_LEVEL")) == "debug" {
		zap.ReplaceGlobals(zap.Must(zap.NewDevelopment()))
	} else {
		config := zap.NewProductionConfig()
		// remove the "caller" key from the log output
		config.EncoderConfig.CallerKey = zapcore.OmitKey
		zap.ReplaceGlobals(zap.Must(config.Build()))
	}
}

func main() {
	mcpServer := mcp.NewServer(&mcp.Implementation{Name: "pod finder", Version: "v1.0.0"}, nil)
	tools := tools.NewTools()
	mcp.AddTool(mcpServer, &mcp.Tool{
		Name: "getKubernetesResource",
		Description: `Fetches a Kubernetes resource from the cluster.
		Parameters:
		name (string, required): The name of the Kubernetes resource.
		kind (string, required): The kind of the Kubernetes resource (e.g. 'Deployment', 'Service').
		cluster (string): The name of the Kubernetes cluster managed by Rancher.
		namespace (string, optional): The namespace of the resource. It must be empty for all namespaces or cluster-wide resources.
		
		Returns:
		The JSON representation of the requested Kubernetes resource.`},
		tools.GetResource)
	// --- SUSE SECURITY TOOLS ---
	mcp.AddTool(mcpServer, &mcp.Tool{
		Name: "getVulnerabilityWorkloadSummary",
		Description: `Get a high-level vulnerability summary (Critical/High counts) for a specific workload.
		Parameters:
		name (string, required): The name of the deployment/pod.
		namespace (string, required): The namespace of the workload.
		cluster (string, required): The cluster name.`,
	}, tools.GetVulnerabilityWorkloadSummary)

	mcp.AddTool(mcpServer, &mcp.Tool{
		Name: "getVulnerabilityList",
		Description: `List specific vulnerabilities for a workload. Can filter by severity or check for a specific CVE.
		Use this when the user asks:
		- "List all vulnerabilities"
		- "List high severity vulnerabilities"
		- "Has CVE-1234-5678 been found?"
		
		Parameters:
		name (string, required): The name of the workload/pod.
		namespace (string, required): The namespace.
		cluster (string, required): The cluster name.
		severity (string, optional): Filter by severity (e.g., "Crtiical", "High", "Medium").
		cve_id (string, optional): Check for a specific CVE ID (e.g., "CVE-2023-1234").`,
	}, tools.GetVulnerabilityList)

	mcp.AddTool(mcpServer, &mcp.Tool{
		Name: "getVulnerabilityStats",
		Description: `Returns a table of vulnerable workloads and their risk counts (Critical/High/Medium).
        Can scan a specific namespace OR the entire cluster.
        
        Use this when the user asks:
        - "Which workloads are affected?" (scans all)
        - "Show me vulnerabilities in the default namespace" (scans namespace)
        - "Give me a security report for the cluster" (scans all)
        
        Parameters:
        cluster (string, required): The cluster name.
        namespace (string, optional): The namespace to scan. If OMITTED or EMPTY, scans the entire cluster.`,
	}, tools.GetVulnerabilityStats)

	handler := mcp.NewStreamableHTTPHandler(func(request *http.Request) *mcp.Server {
		return mcpServer
	}, &mcp.StreamableHTTPOptions{})

	if os.Getenv(skipTLSVerifyEnvVar) == "true" {
		zap.L().Info("MCP Server started!")
		log.Fatal(http.ListenAndServe(":9092", handler))
	} else {
		config, err := rest.InClusterConfig()
		if err != nil {
			log.Fatalf("error creating in-cluster config: %v", err)
		}
		factory, err := core.NewFactoryFromConfig(config)
		if err != nil {
			log.Fatalf("error creating factory: %v", err)
		}

		ctx := context.Background()
		err = server.ListenAndServe(ctx, 9092, 0, handler, &server.ListenOpts{
			Secrets:       factory.Core().V1().Secret(),
			CertNamespace: certNamespace,
			CertName:      certName,
			CAName:        caName,
			TLSListenerConfig: dynamiclistener.Config{
				SANs: []string{
					tlsName,
				},
				FilterCN: dynamiclistener.OnlyAllow(tlsName),
				TLSConfig: &tls.Config{
					MinVersion: tls.VersionTLS12,
					CipherSuites: []uint16{
						tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
						tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
						tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
						tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
						tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
						tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
					},
					ClientAuth: tls.RequestClientCert,
				},
			},
		})
		if err != nil {
			log.Fatalf("error creating tls server: %v", err)
		}
		zap.L().Info("MCP Server with TLS started!")
		<-ctx.Done()
	}
}
