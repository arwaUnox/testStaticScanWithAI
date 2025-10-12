import fs from 'fs'

const inputFile = './classified-findings-gpt5.json'
const outputFile = './classified-findings.sarif'

const data = JSON.parse(fs.readFileSync(inputFile, 'utf-8'))

const sarif = {
  version: '2.1.0',
  runs: [
    {
      tool: {
        driver: {
          name: 'AI Vulnerability Classifier',
          informationUri: 'https://github.com/your-org/your-repo',
          rules: [],
        },
      },
      results: [],
    },
  ],
}

for (const [file, entry] of Object.entries(data)) {
  const issues = entry.issues || []
  for (const issue of issues) {
    const result = issue.validResult || {}
    const vuln = issue.issue || {}

    if (result.result === 'true_positive') {
      sarif.runs[0].results.push({
        ruleId: vuln.vulnerability || 'unknown-issue',
        message: {
          text: `${vuln.explanation}\n\nSeverity: ${result.severity}\n\n${result.explanation}`,
        },
        locations: [
          {
            physicalLocation: {
              artifactLocation: { uri: entry.filePath || file },
            },
          },
        ],
        properties: {
          severity: result.severity || 'unknown',
          exploitation_scenarios: result.exploitation_scenarios || [],
        },
      })
    }
  }
}

fs.writeFileSync(outputFile, JSON.stringify(sarif, null, 2))
console.log(`✅ SARIF report generated at: ${outputFile}`)
