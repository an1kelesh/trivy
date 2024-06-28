package redhatbase

import (
	"bufio"
	"context"
	"os"
	"strings"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	fos "github.com/aquasecurity/trivy/pkg/fanal/analyzer/os"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/fanal/utils"
)

const redosAnalyzerVersion = 1

func init() {
	analyzer.RegisterAnalyzer(&redosOSAnalyzer{})
}

type redosOSAnalyzer struct{}

func (a redosOSAnalyzer) Analyze(_ context.Context, input analyzer.AnalysisInput) (*analyzer.AnalysisResult, error) {
	scanner := bufio.NewScanner(input.Content)
	for scanner.Scan() {
		line := scanner.Text()
		result := redhatRe.FindStringSubmatch(strings.TrimSpace(line))
		if len(result) != 3 {
			return nil, xerrors.New("redos: invalid redos-release")
		}
		return &analyzer.AnalysisResult{
			OS: types.OS{
				Family: types.RedOS,
				Name:   result[2],
			},
		}, nil
	}

	return nil, xerrors.Errorf("redos: %w", fos.AnalyzeOSError)
}

func (a redosOSAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	return utils.StringInSlice(filePath, a.requiredFiles())
}

func (a redosOSAnalyzer) requiredFiles() []string {
	return []string{"etc/redos-release"}
}

func (a redosOSAnalyzer) Type() analyzer.Type {
	return analyzer.TypeRedOS
}

func (a redosOSAnalyzer) Version() int {
	return redosAnalyzerVersion
}
