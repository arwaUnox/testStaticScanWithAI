import { readFileSync, writeFileSync } from 'fs'
import pMap from 'p-map'
import { spawn } from 'child_process'

const report = JSON.parse(readFileSync('./vulnerability-report.json', 'utf-8'))

const generatePrompt = (finding, filePath) => `
You are a senior application security auditor reviewing static code analysis findings from a TypeScript backend project that exposes an HTTP API.

You are given a single finding from file: ${filePath}

Finding structure:
{
  "vulnerability": "${finding.vulnerability}",
  "explanation": "${finding.explanation}",
  "code": "${finding.code}",
  "recommendation": "${finding.recommendation}"
}

Your task:
1. Analyze the provided finding in the context of the backend code.
2. Knowing that some api endpoints like community recipes and community recipe groups are intentionally exposed,and any user can access it and its functionalities.
3. Classify the issue as either "true_positive" or "false_positive"
4. Justify your decision briefly (1–2 sentences)
5. If the issue is a "true_positive", classify it into one of the following severity levels:
   - "Bad design": The issue reflects poor coding or architectural practices but cannot be exploited through the HTTP interface by external users.
   - "Exploitable": The issue introduces a vulnerability that can be exploited by external users through the HTTP API endpoints that this backend exposes, be very careful and think deeply before classifying any finding as exploitable.
6. If it is "Exploitable", describe all possible exploitation scenarios that an external user could perform by making HTTP requests to the backend API. Include:
   - Specific HTTP requests (method, endpoint, headers, body)
   - Expected malicious payloads
   - Step-by-step attack vectors
   - Potential impact on the system

IMPORTANT: A vulnerability is only "Exploitable" if it can be triggered by external users through HTTP requests to the API. Internal code issues that cannot be reached via HTTP endpoints should be classified as "Bad design" at most.
IMPORTANT: Output exactly one JSON object (no code fences, no markdown, no extra text).
IMPORTANT: Wrap THE FINAL JSON OUTPUT ONLY in something like <output> </output> because the final output would be extracted using regex.
Output JSON format:
{
  "result": "true_positive" | "false_positive",
  "explanation": "your explanation here",
  "severity": "Bad design" | "Exploitable" | null,
  "exploitation_scenarios": ["scenario 1", "scenario 2"] | null
}

Please analyze this specific finding and provide your assessment in the requested JSON format.
`
// const generatePrompt = (finding, filePath) => `
// You are a senior application security auditor reviewing static code analysis findings from a TypeScript backend project that exposes an HTTP API.

// You are given a single finding from file: ${filePath}

// Finding structure:
// {
//   "vulnerability": "${finding.vulnerability}",
//   "explanation": "${finding.explanation}",
//   "code": "${finding.code}",
//   "recommendation": "${finding.recommendation}"
// }

// Your task:
// 1. Analyze the provided finding in the context of the backend code.
// 2. Some API endpoints (like community recipes and community recipe groups) are intentionally public and accessible to all users. Vulnerabilities reported in these endpoints are often *false positives* unless they clearly allow external attackers to break out of the intended functionality.
// 3. You must be highly conservative when classifying a finding as "true_positive" and especially "Exploitable".
//    - If there is **any reasonable doubt**, classify the finding as "false_positive".
//    - Only classify as "true_positive" if the vulnerability is unambiguous and undeniably exploitable through an HTTP request.
//    - Only classify as "Exploitable" if you can provide a **complete and realistic attack chain** with HTTP requests that directly show how an attacker could exploit it.
// 4. Classify the issue as either "true_positive" or "false_positive".
// 5. Justify your decision briefly (1–2 sentences).
// 6. If the issue is a "true_positive", classify it into one of the following severity levels:
//    - "Bad design": The issue reflects poor coding or architectural practices but cannot be exploited through the HTTP interface by external users.
//    - "Exploitable": The issue introduces a vulnerability that can be exploited by external users through the HTTP API endpoints. Only assign this if you are absolutely certain and can detail concrete attack steps.
// 7. If it is "Exploitable", describe all possible exploitation scenarios that an external user could perform by making HTTP requests to the backend API. Include:
//    - Specific HTTP requests (method, endpoint, headers, body)
//    - Expected malicious payloads
//    - Step-by-step attack vectors
//    - Potential impact on the system

// IMPORTANT:
// - Do not speculate or assume. If the finding could be benign, classify it as "false_positive".
// - Output strictly in JSON format:
// {
//   "result": "true_positive" | "false_positive",
//   "explanation": "your explanation here",
//   "severity": "Bad design" | "Exploitable" | null,
//   "exploitation_scenarios": ["scenario 1", "scenario 2"] | null
// }
// `
function extractJsonWithRegex(response) {
  const pattern = /<output>(.*?)<\/output>/gs // g = global, s = dotAll
  const matches = [...response.matchAll(pattern)]
  if (matches.length === 0) return null

  const lastMatch = matches[matches.length - 1][1].trim()
  try {
    return JSON.parse(lastMatch)
  } catch {
    return null
  }
}

const results = {}

const classifyIssue = (issue, filePath) => {
  const prompt = generatePrompt(issue, filePath)

  return new Promise((resolve) => {
    const proc = spawn(
      'codex',
      ['exec', '--profile', 'test', '--full-auto'],
      {}
    )
    // const proc = spawn('ccr', ['code', '--print', prompt], {
    //   cwd: process.cwd(),
    //   stdio: ['pipe', 'pipe', 'pipe'],
    // })

    let output = ''
    let error = ''

    proc.stdout.on('data', (data) => {
      output += data.toString()
    })
    proc.stderr.on('data', (data) => {
      error += data.toString()
    })

    proc.on('close', (code) => {
      if (code !== 0) {
        console.error(
          `${filePath}: ${issue.vulnerability} → exited with code ${code}`
        )
        console.error(error)
        return resolve({ issue, result: null, error })
      }

      try {
        // console.log('--- RAW OUTPUT START ---')
        // console.log(output)
        // console.log('--- RAW OUTPUT END ---')
        const jsonResult = extractJsonWithRegex(output)
        console.log('jsonresults is:', jsonResult)

        let validResult = null
        if (
          jsonResult &&
          ['true_positive', 'false_positive'].includes(jsonResult.result) &&
          'explanation' in jsonResult
        ) {
          validResult = jsonResult
        }

        console.log('valid result is:', validResult)
        if (validResult === null) {
          console.warn(
            `${filePath}: ${issue.vulnerability} → No valid results found`
          )
          return resolve({
            issue,
            result: null,
            error: 'No valid result in output',
          })
        }

        resolve({ issue, validResult })
      } catch (e) {
        console.log('Error is:', e)
        console.error(`Failed to parse response:\n${output}`)
        resolve({ issue, result: null, error: e.message })
      }
    })

    proc.stdin.write(prompt)
    proc.stdin.end()
  })
}

const run = async () => {
  for (const file of Object.keys(report)) {
    const issues = report[file].issues || []
    const filePath = report[file].metadata?.filePath

    console.log(`\nProcessing: ${file} (${issues.length} issues)`)

    const classifiedIssues = await pMap(
      issues,
      async (issue) => await classifyIssue(issue, filePath),
      {
        concurrency: 3,
      }
    )

    results[file] = {
      filePath,
      issues: classifiedIssues,
    }
  }

  writeFileSync(
    './classified-findings-gpt5.json',
    JSON.stringify(results, null, 2)
  )
  console.log('\nResults saved to classified-findings-gpt5.json')
}

run()
