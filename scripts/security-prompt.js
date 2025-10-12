import crypto from 'crypto'

export const buildPrompt = (filePath, code) => {
  const fileHash = crypto.createHash('sha256').update(code).digest('hex')
  const prompt = `You are a senior application security expert with deep expertise in modern JavaScript/TypeScript security patterns.
   Your ONLY task is to perform a security analysis of the following **TypeScript** source file and identify concrete, code-level vulnerabilities.
  Focus strictly on these OWASP-related categories:
    - Cross-Site Scripting (XSS) 
    - Cross-Site Request Forgery (CSRF)
    - Broken Access Control (ex:CWE-22 ,CWE-23,CWE-35 ,CWE-284, CWE-285,etc.)
    - Cryptographic Failures (ex:CWE-330 ,CWE-310,CWE-331,CWE-336, etc.)
    - Injection Attacks (SQL, NoSQL, Command, etc.)
    - Insecure Design (ex;CWE-73,CWE-434,CWE-525,CWE-539, etc.)
    - Security Misconfiguration (ex:CWE-614 ,CWE-942,CWE-1032 ,etc.)
    - Use of Vulnerable or Outdated Components (ex:CWE-937,CWE-1035,CWE-1104, etc.)
    - Identification and Authentication Failures (ex:CWE-255, CWE-259, CWE-287,CWE-288,CWE-290,CWE-304 ,CWE-306,CWE-346,CWE-384,CWE-521, etc.)
    - Software and Data Integrity Failures (ex: CWE-345, CWE-353, CWE-426, CWE-494, CWE-502, CWE-565, CWE-784, CWE-829, CWE-830, CWE-915)
    - Security Logging and Monitoring Failures (ex: CWE-117, CWE-223, CWE-532, CWE-778 )
    - Server-Side Request Forgery (SSRF)(CWE-918)

  
  ✅ Output a single valid JSON object** using the **EXACT format** below. Do NOT include explanations, markdown, comments, or extra text outside the JSON. Just return the JSON with the following format.

  
  {
  
    "${fileHash}": {
      "issues":[
      {
        "vulnerability": "Short name of the issue",
        "explanation": "Why this is a vulnerability",
        "code": "Code snippet where it occurs",
        "recommendation": "How to fix or avoid the issue"
      }
    ],
    "metadata": {
      "filePath": "${filePath}",
      "analysisDate": "${new Date().toISOString()}"
    }
  }
  
  Now, analyze the following code from file: ${filePath}
  
  ${code}
  `

  return { prompt, fileHash }
}
