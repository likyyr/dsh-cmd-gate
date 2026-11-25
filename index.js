// dsh-cmd-gate v0.3.2：命令闸门
// 红队三轮（2026-11-25 21:57–22:10）后的最终版：
//   v0.2 → v0.3  ：修 O(n²) 回溯（10KB 换行 1037ms、80KB 挂死 >20s）；剥引号 / here-string / heredoc 防自伤
//   v0.3 → v0.3.1：修 PS 反引号续行、行尾注释豁免、-l 误豁免、BIGDIR 路径形态、cwd、$( ) 命令替换、TIMEOUT= 前缀、rm -Recurse 别名、args 顶层 timeoutMs
//   v0.3.1→v0.3.2：修 RE_TAIL_COMMENT 的 O(n²)（100KB 空格 9192ms）、-Milliseconds 误判、_tmp 扫描豁免、do-echo 段不算超时、相对路径/扩展名文件识别、豁免判断改回原文
//
// 关键：export const name 必须等于 cordis.patch.yml 里的 id（cmd-gate），不是包名
// 逃生舱：命令里带 gate-allow 才放行（写文档引用这些禁令时用）
// 自证：日志默认写系统临时目录的 cmd-gate.log，可用 CMD_GATE_LOG 覆盖

import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'

export const name = 'cmd-gate'
export const inject = ['tools']

const LOG = process.env.CMD_GATE_LOG || path.join(os.tmpdir(), 'cmd-gate.log')
const TRACE = process.env.CMD_GATE_TRACE || path.join(os.tmpdir(), 'gate-trace.on')
const MAX_CMD = 200_000
const MAX_SCRIPT = 65_536

function log(line) {
  try {
    fs.mkdirSync(path.dirname(LOG), { recursive: true })
    fs.appendFileSync(LOG, new Date().toISOString() + ' ' + line + '\n')
  } catch {}
}

const SHELL_TOOLS = new Set(['pwsh', 'ops_bash', 'bash', 'shell', 'a_bash'])

/* ------------------------------------------------------------ 预处理 */

const RE_CRLF = /\r\n?/g
const RE_PS_TICK = /`\n/g
const RE_PS_CONT = /\\\n/g
const RE_PS_BLOCK = /<#[\s\S]*?#>/g
const RE_HERESTR = /@(['"])[\s\S]*?\n\1@/g
const RE_HEREDOC = /<<-?\s*(['"]?)(\w+)\1[\s\S]*?\n\2/g
const RE_LINE_COMMENT = /^[ \t]*#[^\n]*/gm
const RE_TAIL_COMMENT = /[ \t]{1,200}#[^\n]*/g
const RE_SUBCMD = /(?:sh|bash|zsh|cmd|pwsh|powershell|python\d*(?:\.\d+)?)(?:\.exe)?\s+(?:-c|\/c|--command)\s+(['"])([\s\S]*?)\1/gi
const RE_DOLLAR = /\$\(([^()\n]*)\)/g
const RE_QUOTED = /(['"])(?:\\.|(?!\1)[^\\])*\1/g

function norm(raw) {
  let s = String(raw)
  if (s.length > MAX_CMD) s = s.slice(0, MAX_CMD)
  const subs = []
  s = s.replace(RE_SUBCMD, (m0, _q, body) => { subs.push(body); return m0 })
  s = s.replace(RE_DOLLAR, (m0, body) => { subs.push(body); return m0 })
  s = s.replace(RE_CRLF, '\n')
  s = s.replace(RE_PS_TICK, ' ')
  s = s.replace(RE_PS_CONT, ' ')
  s = s.replace(RE_PS_BLOCK, ' ')
  s = s.replace(RE_HERESTR, ' ')
  s = s.replace(RE_HEREDOC, ' ')
  s = s.replace(RE_LINE_COMMENT, ' ')
  if (s.includes('#')) s = s.replace(RE_TAIL_COMMENT, ' ')
  s = s.replace(RE_QUOTED, ' ')
  s = s.replace(/\\/g, '/')
  return (s + '\n' + subs.join('\n')).toLowerCase()
}

/* -------------------------------------------------------------- 规则 */

const THRESH_SLEEP = 20
const THRESH_TIMEOUT_MS = 120_000

// 1) 长 sleep
const RE_WRAP = /\btimeout[ \t]+\d+(?:\.\d+)?[ \t]+/g
const RE_MS = /-milliseconds[ \t]*\d+/g
const RE_SLEEP = /(?:start-sleep|\bsleep\b|time\.sleep[ \t]*\(|timeout[ \t]+\/t)[ \t]*[^;&|\n]{0,40}?(\d+(?:\.\d+)?|0x[0-9a-f]+)/g

// 2) 长命令
const RE_LONG = /\b(?:pip|npm|pnpm|yarn|conda)\b[^\n]{0,30}?\b(?:install|i|add|ci)\b|\b(?:pip3?|python\d*(?:\.\d+)?|py)[\s\S]{0,40}?-m[ \t]+(?:pip|venv)\b|ffmpeg(?:\.exe)?[ \t]/
const RE_HELP = /--help|-h\b|--version|-version\b/

// 3) 显式超时
const RE_ECHO_SEG = /(?:^|[\n;&|])[ \t]*(?:echo|write-host|write-output|set-content|add-content|out-file|git[ \t]+commit|select-string)[^\n]{0,300}/g
const RE_TO_SEC = /\btimeout[ \t]+(\d+)/g
const RE_MAXTIME = /--max-time[= ][ \t]*(\d+)/g
const RE_TIMEOUTSEC = /-timeoutsec[=:\s]*(\d+)/g
const RE_TIMEOUTMS = /timeout_ms['":=\s]+(\d+)/g
const RE_ENV_TIMEOUT = /\btimeout=(\d+)/g

// 4) 递归删除
const RE_RM = /(?:^|[;&|(\n])[ \t]*rm[ \t]+-([a-z]*)/g
const RE_RM_LONG = /(?:^|[;&|(\n])[ \t]*rm[ \t][^\n]{0,40}?--recursive/g
const RE_RMDIR = /(?:^|[;&|(\n])[ \t]*(?:rmdir|rd)[ \t]+\/[sq]/g
const RE_DEL = /(?:^|[;&|(\n])[ \t]*del[ \t]+\/[sq]/g
const RE_RI = /(?:remove-item|\bri\b|\brm\b)[ \t][^\n]{0,200}?-(?:recurse|rec)\b/g
const RE_RI_REV = /-(?:recurse|rec)\b[^\n]{0,200}?(?:remove-item|\bri\b|\brm\b)/g
const RE_FIND_DEL = /\bfind\b[^\n]{0,200}?-delete\b/g
const RE_PIPE_DEL = /\bget-childitem\b[^\n]{0,200}\|[ \t]*(?:remove-item|\bri\b|\brm\b)/g
const RE_SAFE_PATH = /(?:^|[\s"'=:\/\\])_(?:tmp|归档|备份)(?:[\/\\\s"':)]|$)|(?:^|[\s"'=:\/\\])\$env:temp\b|appdata[\/\\]local[\/\\]temp/i
const RE_REBUILD = /(?:^|[\s"'=:\/\\])(?:node_modules|__pycache__|dist|build|\.venv|target|\.cache|cache)(?:[\/\\\s"':)]|$)/i

// 5) 大目录扫描
const RE_SCAN = /(?:^|[;&|(\n])[ \t]*(?:rg|grep[ \t]+-r|find|dir[ \t]+\/s|select-string[^\n]{0,120}-recurse|get-childitem[^\n]{0,120}-recurse)/g
const RE_BIGDIR = /_tools|node_modules|\.git\/|[a-z]:\/|(?:^|[\s"'])\/(?:[ \t;&|"']|$)/
const RE_GLOB = /--glob|-g[ \t]|--include|--exclude/
const RE_PATH_TOKEN = /(?:^|[\s"'])((?:[a-z]:\/|\.{0,2}\/|\/)?[\w.\-/]{1,200}\.[a-z][a-z0-9]{0,5})(?=[\s"'|;&)]|$)/gi
const RE_CWD_DOT = /[ \t]\.(?:[ \t\n;&|"']|$)/

// 7-10) 从 dsh-monitor 规则转来（命令层可判的部分）
const RE_GATE = /(?:check_|verify_|selftest|closure_check|audit_)[^\s]{0,60}\.(?:py|ps1|mjs|cjs)/
const RE_FAKE_OK = /\|\|[ \t]*(?:true|echo)|2>[ \t]*(?:\/dev\/null|\$null)|set[ \t]+\+e/
const RE_SYSDIR = /(?:>|>>|copy|move|cp|mv|del|rm|remove-item|set-content|out-file)[^\n]{0,80}?(?:c:\/windows|program files)/
const RE_SESSLOG = /(?:>|>>|copy|move|del|rm|remove-item|set-content|add-content|out-file)[^\n]{0,80}?\.dsh\/sessions/
const RE_GIT_DANGER = /\bgit[ \t]+(?:reset[ \t]+--hard|checkout[ \t]+--[ \t]+\.|clean[ \t]+-[a-z]*f|push[ \t]+(?:-f|--force))/

const RULES_EXTRA = 4

function maxInt(re, s) {
  let max = -Infinity
  for (const m of s.matchAll(re)) {
    const n = Number(m[1])
    if (Number.isFinite(n) && n > max) max = n
  }
  return max
}

function anyMatch(re, s) {
  re.lastIndex = 0
  return re.exec(s) !== null
}

function targetIsFile(cmd) {
  RE_PATH_TOKEN.lastIndex = 0
  for (const m of cmd.matchAll(RE_PATH_TOKEN)) {
    try { if (fs.statSync(m[1]).isFile()) return true } catch {}
  }
  return false
}

function hasRecursiveDelete(cmd) {
  RE_RM.lastIndex = 0
  for (const m of cmd.matchAll(RE_RM)) if (m[1].includes('r')) return true
  return anyMatch(RE_RM_LONG, cmd) || anyMatch(RE_RMDIR, cmd) || anyMatch(RE_DEL, cmd) ||
    anyMatch(RE_RI, cmd) || anyMatch(RE_RI_REV, cmd) || anyMatch(RE_FIND_DEL, cmd) || anyMatch(RE_PIPE_DEL, cmd)
}

function expandVars(s) {
  const vars = {}
  for (const m of s.matchAll(/\$(\w+)[ \t]*=[ \t]*(\d+)/g)) vars[m[1]] = m[2]
  if (!Object.keys(vars).length) return s
  return s.replace(/\$(\w+)/g, (m0, k) => (vars[k] !== undefined ? vars[k] : m0))
}

function matchRule(cmd, args, raw) {
  if (cmd.includes('gate-allow')) return undefined
  cmd = expandVars(cmd)
  const rawClean = raw.replace(RE_TAIL_COMMENT, ' ')
  const rawNorm = rawClean.toLowerCase().replace(/\\/g, '/')

  // 1) 长 sleep
  if (cmd.includes('sleep') || cmd.includes('timeout /t')) {
    const bare = cmd.replace(RE_WRAP, ' ').replace(RE_MS, ' ')
    const n = maxInt(RE_SLEEP, bare)
    if (n >= THRESH_SLEEP) {
      return '【命令闸门·sleep】禁止长 sleep（' + n + 's ≥ ' + THRESH_SLEEP + 's）。改用 run_in_background: true 起后台 job，再用 job_output 收结果——睡着的时候什么都干不了。'
    }
  }

  // 2) 长命令前台
  if (!RE_HELP.test(cmd) && (cmd.includes('install') || cmd.includes('venv') || cmd.includes('ffmpeg') || cmd.includes('add') || cmd.includes('create'))) {
    if (anyMatch(RE_LONG, cmd) && !args.run_in_background) {
      return '【命令闸门·长命令】装包/转码/建 venv 这类命令必须加 run_in_background: true。前台跑会卡住整轮（实测有装包撞 600s 超时白跑 10 分钟）。'
    }
  }

  // 3) 显式超时（echo/写文件/git commit 段里的字面量不算）
  if (cmd.includes('timeout') || cmd.includes('max-time')) {
    const probe = cmd.replace(RE_ECHO_SEG, ' ')
    const t = Math.max(
      maxInt(RE_TO_SEC, probe),
      maxInt(RE_MAXTIME, probe),
      maxInt(RE_TIMEOUTSEC, probe),
      maxInt(RE_TIMEOUTMS, probe) / 1000,
      maxInt(RE_ENV_TIMEOUT, probe)
    )
    if (t > 120) {
      return '【命令闸门·超时】这条命令的超时设了 ' + t + 's（>120s）。等于把"卡住"合法化——只有转后台才需要长超时，前台命令请压到 120s 内。'
    }
  }
  for (const k of ['timeoutMs', 'timeout_ms', 'timeout']) {
    const v = Number(args[k])
    if (Number.isFinite(v) && v > THRESH_TIMEOUT_MS) {
      return '【命令闸门·超时】arguments.' + k + ' = ' + v + '（>120000ms）。前台命令请压到 120s 内。'
    }
  }

  // 4) 递归删除（豁免用原文判，剥引号会连 "$env:TEMP\build" 一起剥掉）
  if (cmd.includes('rm') || cmd.includes('remove-item') || cmd.includes('del ') || cmd.includes('find')) {
    if (hasRecursiveDelete(cmd) && !RE_SAFE_PATH.test(rawClean) && !RE_REBUILD.test(rawClean)) {
      return '【命令闸门·递归删除】递归删除前必须先核对绝对路径、并确认目标不含 _归档/原始凭证/项目档案。先备份到 _归档\\_备份_<名>_<日期> 再删；_tmp 下的临时文件可直接删。'
    }
  }

  // 5) 大目录扫描
  if (cmd.includes('rg ') || cmd.includes('grep') || cmd.includes('find') || cmd.includes('childitem')) {
    const scanHit = anyMatch(RE_SCAN, cmd)
    const bigHit = RE_BIGDIR.test(cmd) || (RE_CWD_DOT.test(cmd) && /_tools|node_modules/.test(process.cwd().toLowerCase()))
    if (scanHit && bigHit && !RE_GLOB.test(cmd) && !RE_SAFE_PATH.test(rawClean) && !targetIsFile(cmd)) {
      return '【命令闸门·大目录扫描】这条命令在扫大目录（_tools 全目录 7.9GB/72865 文件会 >15 秒不返回）。改用 ops_grep/ops_glob 加 glob 限定，或 rg 加 --glob。'
    }
  }

  // 7) 门禁伪装（从 dsh-monitor C2 转来：门禁脚本带 || echo / 2>/dev/null / set +e 等于没跑）
  if (RE_GATE.test(cmd) && RE_FAKE_OK.test(cmd)) {
    return '【命令闸门·门禁伪装】门禁/校验脚本后面跟了 || echo / 2>/dev/null / set +e，等于把失败吞掉、假装通过。出错要让它报错，0 ERROR 才算过。'
  }

  // 8) 系统目录写入（从 dsh-monitor D2 转来）
  if (RE_SYSDIR.test(rawNorm)) {
    return '【命令闸门·系统目录】这条命令在写 C:\\Windows / Program Files 这类系统目录。真要改先确认路径并备份，命令里带 gate-allow。'
  }

  // 9) 会话日志（从 dsh-monitor D4 转来）
  if (RE_SESSLOG.test(rawNorm)) {
    return '【命令闸门·会话日志】这条命令在改 .dsh/sessions 下的会话记录。手工改会话日志会毁掉回溯依据，真要改先说明理由并带 gate-allow。'
  }

  // 10) git 危险操作（dsh-monitor D1 的 git 部分，原插件没有）
  if (RE_GIT_DANGER.test(cmd)) {
    return '【命令闸门·git】这条 git 命令会丢改动（reset --hard / checkout -- . / clean -f / push -f）。先 git stash 或 branch 备份，命令里带 gate-allow 才能真正执行。'
  }

  return undefined
}

/* ---------------------------------------------------------- 重复调用检测 */

const READ_TOOLS = new Set(['read', 'ops_inspect_local_file', 'ops_grep', 'ops_glob'])
const RECENT = []
const R_WINDOW_MS = 90_000
const R_MAX_BEFORE_DENY = 2   // 已发生 2 次，第 3 次拒

function sigOf(tool, args) {
  const keys = ['command', 'path', 'file_path', 'offset', 'limit', 'pattern', 'glob']
  const o = {}
  for (const k of keys) {
    if (args[k] !== undefined && args[k] !== null) o[k] = String(args[k]).slice(0, 200)
  }
  return tool + '|' + JSON.stringify(o)
}

function pruneRecent(now) {
  while (RECENT.length && now - RECENT[0].ts > R_WINDOW_MS) RECENT.shift()
}

function repeatReason(tool, args) {
  const now = Date.now()
  pruneRecent(now)
  const sig = sigOf(tool, args)
  let n = 0
  for (const r of RECENT) if (r.sig === sig) n++
  if (n >= R_MAX_BEFORE_DENY) {
    return '【命令闸门·重复调用】同一个调用（同工具、同参数）90 秒内已经跑过 ' + n + ' 次，这是第 ' +
      (n + 1) + ' 次。先看手上已有的结果，别重复劳动；确实要重跑，命令里带 gate-allow。'
  }
  return undefined
}

/* -------------------------------------------------------------- 入口 */

function pickArgs(exec) {
  let a = exec && (exec.arguments ?? exec.args ?? exec.input ?? exec.params)
  if (!a) return {}
  if (typeof a === 'string') {
    try { a = JSON.parse(a) } catch { return {} }
  }
  return a && typeof a === 'object' ? a : {}
}

function readScript(p) {
  try {
    const st = fs.statSync(p)
    if (!st.isFile() || st.size > MAX_SCRIPT) return ''
    return fs.readFileSync(p, 'utf8').slice(0, MAX_SCRIPT)
  } catch { return '' }
}

export function check(exec) {
  try {
    const toolName = String(exec && exec.name != null ? exec.name : (exec && exec.toolName) || '')
    const isShell = SHELL_TOOLS.has(toolName)
    const isRead = READ_TOOLS.has(toolName)
    if (!isShell && !isRead) return undefined
    const args = pickArgs(exec)
    if (!args || typeof args !== 'object') return undefined

    const bg = args.run_in_background === true || args.runInBackground === true ||
      args.background === true || String(args.run_in_background) === 'true'
    const eff = Object.assign({}, exec && typeof exec === 'object' ? exec : {}, args, { run_in_background: bg })

    if (isRead) {
      const repRead = repeatReason(toolName, eff)
      if (repRead) return repRead
      RECENT.push({ sig: sigOf(toolName, eff), ts: Date.now() })
      if (RECENT.length > 200) RECENT.shift()
      return undefined
    }

    const parts = []
    const rawCmd = args.command ?? args.cmd ?? args.script
    if (rawCmd != null) parts.push(Array.isArray(rawCmd) ? rawCmd.join(' ') : String(rawCmd))
    if (typeof args.script_path === 'string' && args.script_path) {
      const body = readScript(args.script_path)
      if (body) parts.push(body)
    }

    const raw = parts.join('\n')
    const cmd = norm(raw)
    if (!cmd.trim()) return undefined

    const rep = repeatReason(toolName, eff)
    if (rep) return rep
    const reason = matchRule(cmd, eff, raw)
    if (!reason) {
      RECENT.push({ sig: sigOf(toolName, eff), ts: Date.now() })
      if (RECENT.length > 200) RECENT.shift()
    }
    return reason
  } catch {
    return undefined
  }
}

/* -------------------------------------------------------------- 挂载 */

export function apply(ctx) {
  log('loaded: 命令闸门 v0.3.4 | tools.guard=' + (typeof ctx.tools?.guard))
  if (typeof ctx.tools?.guard !== 'function') { log('ctx.tools.guard 不可用，闸门不生效'); return }
  ctx.tools.guard((exec) => {
    try {
      if (fs.existsSync(TRACE)) {
        try { log('CALL ' + JSON.stringify({ t: exec && exec.name, c: exec && exec.callId, r: exec && exec.rootCallId })) } catch {}
      }
      const reason = check(exec)
      if (reason) {
        const id = (reason.match(/【命令闸门·([^】]+)】/) || [])[1] || '?'
        log('DENY[' + id + '] ' + JSON.stringify({ tool: exec && exec.name }))
      }
      return reason
    } catch {
      return undefined
    }
  })
  log('guard registered')
}
