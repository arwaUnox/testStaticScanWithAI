import fs from 'fs'
import path from 'path'
import fetch from 'node-fetch'
import { AbortController } from 'node-abort-controller'
import async from 'async'
import { buildPrompt } from './security-prompt.js'
import extract from 'extract-json-from-string'

const FIREWORKS_API_KEY = 'fw_3ZMVCE75ayMd3AzuTdJrrky5'
const MODEL = 'accounts/fireworks/models/deepseek-r1'
const MAX_TOKENS = 4096
const FOLDER_TO_SCAN = './scripts'
const OUTPUT_FILE = './vulnerability-report.json'
const CONCURRENCY = 5

const vulnerabilityReport = (() => {
  if (fs.existsSync(OUTPUT_FILE)) {
    try {
      const previousData = fs.readFileSync(OUTPUT_FILE, 'utf-8')
      console.log(
        `Loaded previous report with ${
          Object.keys(JSON.parse(previousData)).length
        } entries`
      )
      return JSON.parse(previousData)
    } catch (err) {
      console.warn(`⚠️ Failed to load previous report: ${err.message}`)
    }
  }
  return {}
})()

// const queue = new PQueue({ concurrency: CONCURRENCY })

const scanFile = async (filePath) => {
  const code = fs.readFileSync(filePath, 'utf-8')
  const { prompt, fileHash } = buildPrompt(filePath, code)
  const controller = new AbortController()
  const timeout = setTimeout(() => controller.abort(), 60000)
  if (vulnerabilityReport[fileHash]) {
    console.log(`Skipping already scanned file: ${filePath}`)
    return
  }

  console.log(`Scanning ${filePath}...`)
  let result
  try {
    result = await fetch('https://api.fireworks.ai/inference/v1/completions', {
      method: 'POST',
      headers: {
        Accept: 'application/json',
        'Content-Type': 'application/json',
        Authorization: `Bearer ${FIREWORKS_API_KEY}`,
      },
      body: JSON.stringify({
        model: MODEL,
        max_tokens: MAX_TOKENS,
        temperature: 0.6,
        top_p: 1,
        top_k: 40,
        presence_penalty: 0,
        frequency_penalty: 0,
        prompt,
      }),
      signal: controller.signal,
    })
  } catch (err) {
    console.error(`Timeout or error while fetching ${filePath}:`, err.message)
    vulnerabilityReport[filePath] = [
      {
        vulnerability: 'Timeout',
        explanation: 'The request to the LLM timed out or failed unexpectedly.',
        code: '',
        recommendation: 'Retry later or check API responsiveness.',
        rawOutput: '',
      },
    ]
    return
  } finally {
    clearTimeout(timeout)
  }

  const data = await result.json()
  const raw = data?.choices?.[0]?.text?.trim()

  if (!raw) {
    console.warn(` Empty response for ${filePath}`)
    return
  }

  try {
    const parsedList = extract(raw)
    const validResult = parsedList.find(
      (obj) =>
        typeof obj === 'object' &&
        Object.values(obj).some(
          (v) => typeof v === 'object' && v.issues && v.metadata
        )
    )

    if (!validResult) {
      throw new Error('No valid vulnerability object found in parsed list')
    }
    for (const [hash, report] of Object.entries(validResult)) {
      if (
        typeof report === 'object' &&
        Array.isArray(report.issues) &&
        report.metadata
      ) {
        vulnerabilityReport[hash] = {
          issues: report.issues,
          metadata: report.metadata,
        }
      }
    }
  } catch (e) {
    console.error(`Failed to parse JSON for ${filePath}:`, e.message)
    vulnerabilityReport[filePath] = [
      {
        vulnerability: 'ParseError',
        explanation: 'Could not parse model response as JSON',
        code: '',
        recommendation: 'Ensure model returns valid JSON only.',
        rawOutput: raw,
      },
    ]
  }
}

const collectFiles = (folderPath, fileList = []) => {
  const entries = fs.readdirSync(folderPath)

  for (const entry of entries) {
    const fullPath = path.join(folderPath, entry)
    const stat = fs.statSync(fullPath)

    if (stat.isDirectory()) {
      collectFiles(fullPath, fileList)
    } else if (entry.endsWith('.ts') || entry.endsWith('.js')) {
      fileList.push(fullPath)
    }
  }

  return fileList
}

const main = async () => {
  console.log(`Starting scan of folder: ${FOLDER_TO_SCAN}`)
  const q = async.queue(async (task) => {
    await scanFile(task.name)
    console.log(`Finished scanning ${task.name}`)
  }, CONCURRENCY)
  q.drain(function () {
    fs.writeFileSync(
      OUTPUT_FILE,
      JSON.stringify(vulnerabilityReport, null, 2),
      'utf-8'
    )
    console.log(`Done! Vulnerabilities saved to: ${OUTPUT_FILE}`)
  })
  q.error(function (err, task) {
    console.error('task experienced an error')
  })
  const files = collectFiles(FOLDER_TO_SCAN)

  for (const file of files) {
    q.push({ name: file })
  }
}

main()
