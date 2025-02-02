package report

import (
	"testing"

	"github.com/stretchr/testify/assert"

	dbTypes "github.com/an1kelesh/trivy-db/pkg/types"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/types"
)

var (
	deployOrionWithMisconfigs = Resource{
		Namespace: "default",
		Kind:      "Deploy",
		Name:      "orion",
		Metadata: types.Metadata{
			RepoTags: []string{
				"alpine:3.14",
			},
			RepoDigests: []string{
				"alpine:3.14@sha256:8fe1727132b2506c17ba0e1f6a6ed8a016bb1f5735e43b2738cd3fd1979b6260",
			},
		},
		Results: types.Results{
			{
				Misconfigurations: []types.DetectedMisconfiguration{
					{
						ID:       "ID100",
						Status:   types.StatusFailure,
						Severity: "LOW",
					},
					{
						ID:       "ID101",
						Status:   types.StatusFailure,
						Severity: "MEDIUM",
					},
					{
						ID:       "ID102",
						Status:   types.StatusFailure,
						Severity: "HIGH",
					},
					{
						ID:       "ID103",
						Status:   types.StatusFailure,
						Severity: "CRITICAL",
					},
					{
						ID:       "ID104",
						Status:   types.StatusFailure,
						Severity: "UNKNOWN",
					},
					{
						ID:       "ID105",
						Status:   types.StatusFailure,
						Severity: "LOW",
					},
					{
						ID:       "ID106",
						Status:   types.StatusFailure,
						Severity: "HIGH",
					},
				},
			},
		},
	}

	deployOrionWithVulns = Resource{
		Namespace: "default",
		Kind:      "Deploy",
		Name:      "orion",
		Metadata: types.Metadata{
			RepoTags: []string{
				"alpine:3.14",
			},
			RepoDigests: []string{
				"alpine:3.14@sha256:8fe1727132b2506c17ba0e1f6a6ed8a016bb1f5735e43b2738cd3fd1979b6260",
			},
		},
		Results: types.Results{
			{
				Vulnerabilities: []types.DetectedVulnerability{
					{
						VulnerabilityID: "CVE-2022-1111",
						Vulnerability:   dbTypes.Vulnerability{Severity: "LOW"},
					},
					{
						VulnerabilityID: "CVE-2022-2222",
						Vulnerability:   dbTypes.Vulnerability{Severity: "MEDIUM"},
					},
					{
						VulnerabilityID: "CVE-2022-3333",
						Vulnerability:   dbTypes.Vulnerability{Severity: "HIGH"},
					},
					{
						VulnerabilityID: "CVE-2022-4444",
						Vulnerability:   dbTypes.Vulnerability{Severity: "CRITICAL"},
					},
					{
						VulnerabilityID: "CVE-2022-5555",
						Vulnerability:   dbTypes.Vulnerability{Severity: "UNKNOWN"},
					},
					{
						VulnerabilityID: "CVE-2022-6666",
						Vulnerability:   dbTypes.Vulnerability{Severity: "CRITICAL"},
					},
					{
						VulnerabilityID: "CVE-2022-7777",
						Vulnerability:   dbTypes.Vulnerability{Severity: "MEDIUM"},
					},
				},
			},
		},
	}

	deployOrionWithBothVulnsAndMisconfigs = Resource{
		Namespace: "default",
		Kind:      "Deploy",
		Name:      "orion",
		Metadata: types.Metadata{
			RepoTags: []string{
				"alpine:3.14",
			},
			RepoDigests: []string{
				"alpine:3.14@sha256:8fe1727132b2506c17ba0e1f6a6ed8a016bb1f5735e43b2738cd3fd1979b6260",
			},
		},
		Results: types.Results{
			{
				Misconfigurations: []types.DetectedMisconfiguration{
					{
						ID:       "ID100",
						Status:   types.StatusFailure,
						Severity: "LOW",
					},
					{
						ID:       "ID101",
						Status:   types.StatusFailure,
						Severity: "MEDIUM",
					},
					{
						ID:       "ID102",
						Status:   types.StatusFailure,
						Severity: "HIGH",
					},
					{
						ID:       "ID103",
						Status:   types.StatusFailure,
						Severity: "CRITICAL",
					},
					{
						ID:       "ID104",
						Status:   types.StatusFailure,
						Severity: "UNKNOWN",
					},
					{
						ID:       "ID105",
						Status:   types.StatusFailure,
						Severity: "LOW",
					},
					{
						ID:       "ID106",
						Status:   types.StatusFailure,
						Severity: "HIGH",
					},
				},
			},
			{
				Vulnerabilities: []types.DetectedVulnerability{
					{
						VulnerabilityID: "CVE-2022-1111",
						Vulnerability:   dbTypes.Vulnerability{Severity: "LOW"},
					},
					{
						VulnerabilityID: "CVE-2022-2222",
						Vulnerability:   dbTypes.Vulnerability{Severity: "MEDIUM"},
					},
					{
						VulnerabilityID: "CVE-2022-3333",
						Vulnerability:   dbTypes.Vulnerability{Severity: "HIGH"},
					},
					{
						VulnerabilityID: "CVE-2022-4444",
						Vulnerability:   dbTypes.Vulnerability{Severity: "CRITICAL"},
					},
					{
						VulnerabilityID: "CVE-2022-5555",
						Vulnerability:   dbTypes.Vulnerability{Severity: "UNKNOWN"},
					},
					{
						VulnerabilityID: "CVE-2022-6666",
						Vulnerability:   dbTypes.Vulnerability{Severity: "CRITICAL"},
					},
					{
						VulnerabilityID: "CVE-2022-7777",
						Vulnerability:   dbTypes.Vulnerability{Severity: "MEDIUM"},
					},
				},
			},
		},
	}

	cronjobHelloWithVulns = Resource{
		Namespace: "default",
		Kind:      "Cronjob",
		Name:      "hello",
		Metadata: types.Metadata{
			RepoTags: []string{
				"alpine:3.14",
			},
			RepoDigests: []string{
				"alpine:3.14@sha256:8fe1727132b2506c17ba0e1f6a6ed8a016bb1f5735e43b2738cd3fd1979b6260",
			},
		},
		Results: types.Results{
			{Vulnerabilities: []types.DetectedVulnerability{{VulnerabilityID: "CVE-2020-9999"}}},
		},
	}

	podPrometheusWithMisconfigs = Resource{
		Namespace: "default",
		Kind:      "Pod",
		Name:      "prometheus",
		Metadata: types.Metadata{
			RepoTags: []string{
				"alpine:3.14",
			},
			RepoDigests: []string{
				"alpine:3.14@sha256:8fe1727132b2506c17ba0e1f6a6ed8a016bb1f5735e43b2738cd3fd1979b6260",
			},
		},
		Results: types.Results{
			{Misconfigurations: []types.DetectedMisconfiguration{{ID: "ID100"}}},
		},
	}

	roleWithMisconfig = Resource{
		Namespace: "default",
		Kind:      "Role",
		Name:      "system::leader-locking-kube-controller-manager",
		Results: types.Results{
			{
				Misconfigurations: []types.DetectedMisconfiguration{
					{
						ID:       "ID100",
						Status:   types.StatusFailure,
						Severity: "MEDIUM",
					},
				},
			},
		},
	}

	deployLuaWithSecrets = Resource{
		Namespace: "default",
		Kind:      "Deploy",
		Name:      "lua",
		Results: types.Results{
			{
				Secrets: []ftypes.SecretFinding{
					{
						RuleID:   "secret1",
						Severity: "CRITICAL",
					},
					{
						RuleID:   "secret2",
						Severity: "MEDIUM",
					},
				},
			},
		},
	}

	apiseverPodWithMisconfigAndInfra = Resource{
		Namespace: "kube-system",
		Kind:      "Pod",
		Name:      "kube-apiserver",
		Results: types.Results{
			{
				Misconfigurations: []types.DetectedMisconfiguration{
					{
						ID:       "KSV-ID100",
						Status:   types.StatusFailure,
						Severity: "LOW",
					},
					{
						ID:       "KSV-ID101",
						Status:   types.StatusFailure,
						Severity: "MEDIUM",
					},
					{
						ID:       "KSV-ID102",
						Status:   types.StatusFailure,
						Severity: "HIGH",
					},

					{
						ID:       "KCV-ID100",
						Status:   types.StatusFailure,
						Severity: "LOW",
					},
					{
						ID:       "KCV-ID101",
						Status:   types.StatusFailure,
						Severity: "MEDIUM",
					},
				},
			},
		},
	}
)

func TestReport_consolidate(t *testing.T) {
	tests := []struct {
		name             string
		report           Report
		expectedFindings map[string]Resource
	}{
		{
			name: "report with both misconfigs and vulnerabilities",
			report: Report{
				Resources: []Resource{
					deployOrionWithVulns,
					cronjobHelloWithVulns,
					deployOrionWithMisconfigs,
					podPrometheusWithMisconfigs,
				},
			},
			expectedFindings: map[string]Resource{
				"default/deploy/orion":   deployOrionWithBothVulnsAndMisconfigs,
				"default/cronjob/hello":  cronjobHelloWithVulns,
				"default/pod/prometheus": podPrometheusWithMisconfigs,
			},
		},
		{
			name: "report with only misconfigurations",
			report: Report{
				Resources: []Resource{
					deployOrionWithMisconfigs,
					podPrometheusWithMisconfigs,
				},
			},
			expectedFindings: map[string]Resource{
				"default/deploy/orion":   deployOrionWithMisconfigs,
				"default/pod/prometheus": podPrometheusWithMisconfigs,
			},
		},
		{
			name: "report with only vulnerabilities",
			report: Report{
				Resources: []Resource{
					deployOrionWithVulns,
					cronjobHelloWithVulns,
				},
			},
			expectedFindings: map[string]Resource{
				"default/deploy/orion":  deployOrionWithVulns,
				"default/cronjob/hello": cronjobHelloWithVulns,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			consolidateReport := tt.report.consolidate()
			for _, f := range consolidateReport.Findings {
				key := f.fullname()

				expected, found := tt.expectedFindings[key]
				if !found {
					t.Errorf("key not found: %s", key)
				}

				assert.Equal(t, expected, f)
			}
		})
	}
}

func TestResource_fullname(t *testing.T) {
	tests := []struct {
		expected string
		resource Resource
	}{
		{
			"default/deploy/orion",
			deployOrionWithBothVulnsAndMisconfigs,
		},
		{
			"default/deploy/orion",
			deployOrionWithMisconfigs,
		},
		{
			"default/cronjob/hello",
			cronjobHelloWithVulns,
		},
		{
			"default/pod/prometheus",
			podPrometheusWithMisconfigs,
		},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.resource.fullname())
		})
	}
}

func TestResourceFailed(t *testing.T) {
	tests := []struct {
		name     string
		report   Report
		expected bool
	}{
		{
			name: "report with both misconfigs and vulnerabilities",
			report: Report{
				Resources: []Resource{
					deployOrionWithVulns,
					cronjobHelloWithVulns,
					deployOrionWithMisconfigs,
					podPrometheusWithMisconfigs,
				},
			},
			expected: true,
		},
		{
			name: "report with only misconfigurations",
			report: Report{
				Resources: []Resource{
					deployOrionWithMisconfigs,
					podPrometheusWithMisconfigs,
				},
			},
			expected: true,
		},
		{
			name: "report with only vulnerabilities",
			report: Report{
				Resources: []Resource{
					deployOrionWithVulns,
					cronjobHelloWithVulns,
				},
			},
			expected: true,
		},
		{
			name:     "report without vulnerabilities and misconfigurations",
			report:   Report{},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.report.Failed())
		})
	}
}

func Test_rbacResource(t *testing.T) {
	tests := []struct {
		name      string
		misConfig Resource
		want      bool
	}{
		{
			name:      "rbac Role resources",
			misConfig: Resource{Kind: "Role"},
			want:      true,
		},
		{
			name:      "rbac ClusterRole resources",
			misConfig: Resource{Kind: "ClusterRole"},
			want:      true,
		},
		{
			name:      "rbac RoleBinding resources",
			misConfig: Resource{Kind: "RoleBinding"},
			want:      true,
		},
		{
			name:      "rbac ClusterRoleBinding resources",
			misConfig: Resource{Kind: "ClusterRoleBinding"},
			want:      true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := rbacResource(test.misConfig)
			assert.Equal(t, test.want, got)
		})
	}
}

func Test_separateMisconfigReports(t *testing.T) {
	k8sReport := Report{
		Resources: []Resource{
			{Kind: "Role"},
			{Kind: "Deployment"},
			{Kind: "StatefulSet"},
			{
				Kind:      "Pod",
				Namespace: "kube-system",
				Results: []types.Result{
					{Misconfigurations: []types.DetectedMisconfiguration{{ID: "KCV-0001"}}},
					{Misconfigurations: []types.DetectedMisconfiguration{{ID: "KSV-0001"}}},
				},
			},
		},
	}

	tests := []struct {
		name            string
		k8sReport       Report
		scanners        types.Scanners
		components      []string
		expectedReports []Report
	}{
		{
			name:      "Config, Rbac, and Infra Reports",
			k8sReport: k8sReport,
			scanners: types.Scanners{
				types.MisconfigScanner,
				types.RBACScanner,
			},
			components: []string{
				workloadComponent,
				infraComponent,
			},
			expectedReports: []Report{
				// the order matter for the test
				{
					Resources: []Resource{
						{Kind: "Deployment"},
						{Kind: "StatefulSet"},
						{Kind: "Pod"},
					},
				},
				{Resources: []Resource{{Kind: "Role"}}},
				{Resources: []Resource{{Kind: "Pod"}}},
			},
		},
		{
			name:      "Config and Infra for the same resource",
			k8sReport: k8sReport,
			scanners:  types.Scanners{types.MisconfigScanner},
			components: []string{
				workloadComponent,
				infraComponent,
			},
			expectedReports: []Report{
				// the order matter for the test
				{
					Resources: []Resource{
						{Kind: "Deployment"},
						{Kind: "StatefulSet"},
						{Kind: "Pod"},
					},
				},
				{Resources: []Resource{{Kind: "Pod"}}},
			},
		},
		{
			name:      "Role Report Only",
			k8sReport: k8sReport,
			scanners:  types.Scanners{types.RBACScanner},
			expectedReports: []Report{
				{Resources: []Resource{{Kind: "Role"}}},
			},
		},
		{
			name:       "Config Report Only",
			k8sReport:  k8sReport,
			scanners:   types.Scanners{types.MisconfigScanner},
			components: []string{workloadComponent},
			expectedReports: []Report{
				{
					Resources: []Resource{
						{Kind: "Deployment"},
						{Kind: "StatefulSet"},
						{Kind: "Pod"},
					},
				},
			},
		},
		{
			name:       "Infra Report Only",
			k8sReport:  k8sReport,
			scanners:   types.Scanners{types.MisconfigScanner},
			components: []string{infraComponent},
			expectedReports: []Report{
				{Resources: []Resource{{Kind: "Pod"}}},
			},
		},

		// TODO: add vuln only
		// TODO: add secret only
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reports := SeparateMisconfigReports(tt.k8sReport, tt.scanners, tt.components)
			assert.Equal(t, len(tt.expectedReports), len(reports))

			for i := range reports {
				assert.Equal(t, len(tt.expectedReports[i].Resources), len(reports[i].Report.Resources))
				for j, m := range tt.expectedReports[i].Resources {
					assert.Equal(t, m.Kind, reports[i].Report.Resources[j].Kind)
				}
			}
		})
	}
}
