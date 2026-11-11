'use strict';
const $ = id => document.getElementById(id);
const token = document.querySelector('meta[name="agentwatch-token"]').content;
const maxBytes = 2000000;
const sample = [
  {event_id:'sample-read',session_id:'approved-research',tool:'http',destination:'https://docs.example.com/guide',bytes_sent:50,sensitive:false,approved:true},
  {event_id:'sample-external',session_id:'unexpected-destination',tool:'http',destination:'https://unapproved.example/upload',bytes_sent:500,sensitive:true,approved:true},
  {event_id:'sample-write',session_id:'missing-recorded-approval',tool:'write',bytes_sent:0,sensitive:false,approved:false}
].map(e => JSON.stringify(e)).join('\n') + '\n';
const rules = {
  MISSING_DESTINATION:'A network action or transfer has no recorded destination.',
  UNAPPROVED_DESTINATION:'The recorded destination is outside your approved website list.',
  SENSITIVE_EXTERNAL_TRANSFER:'Data marked sensitive was sent to a destination outside your approved list.',
  ACTION_WITHOUT_APPROVAL:'A write or shell action has no recorded approval.'
};
let report = null;
let downloads = [];
let shown = 20;
let busy = false;
function node(tag, text, className) {
  const el = document.createElement(tag);
  el.textContent = text;
  if (className) el.className = className;
  return el;
}
function clearResults() {
  downloads.forEach(url => URL.revokeObjectURL(url));
  downloads = [];
  report = null;
  $('source').textContent = '';
  $('cards').replaceChildren();
  $('results').hidden = true;
  $('empty').hidden = false;
  $('clear').disabled = true;
  $('html-download').removeAttribute('href');
  $('json-download').removeAttribute('href');
}
function status(text, error = false) {
  $('status').textContent = text;
  $('status').classList.toggle('error', error);
}
function blobUrl(content, type) {
  const url = URL.createObjectURL(new Blob([content], {type}));
  downloads.push(url);
  return url;
}
function showCards() {
  if (!report) return;
  const rows = report.sessions.filter(r => !$('review-only').checked || r.review);
  $('cards').replaceChildren();
  rows.slice(0, shown).forEach(row => {
    const card = node('article', '', 'session');
    card.append(node('h3', row.session_id));
    card.append(node('span', row.review ? 'Needs review' : 'No policy findings', row.review ? 'badge' : 'badge clear'));
    card.append(node('p', `${row.features.calls} recorded actions · ${row.findings.length} flagged events`));
    if (row.findings.length) {
      const reasons = node('ul', '');
      [...new Set(row.findings.flatMap(f => f.rules))].forEach(rule => reasons.append(node('li', rules[rule] || rule)));
      card.append(reasons);
    }
    const details = node('details', '');
    details.append(node('summary', 'Show recorded evidence'));
    // Build evidence only on expansion, bounded per session for responsiveness.
    details.addEventListener('toggle', () => {
      if (!details.open || details.dataset.loaded) return;
      details.dataset.loaded = 'true';
      const findings = row.findings.slice(0,100);
      findings.forEach(f => {
        const evidence = node('div', '', 'evidence');
        evidence.append(node('p', `Event ${f.event_id} · Input line ${f.line}`));
        f.rules.forEach(rule => evidence.append(node('p', rules[rule] || rule)));
        details.append(evidence);
      });
      if (row.findings.length > 100) details.append(node('p', 'Showing the first 100 flagged events. Download the report for all evidence.'));
      if (!row.findings.length) details.append(node('p', 'No policy findings. No machine-learning assessment was performed.'));
      details.append(node('p', `Recorded event IDs: ${row.evidence_ids.slice(0,100).join(', ')}${row.evidence_ids.length > 100 ? ' (first 100 shown)' : ''}`));
    });
    card.append(details);
    $('cards').append(card);
  });
  $('list-summary').textContent = rows.length ? `Showing ${Math.min(shown,rows.length)} of ${rows.length} sessions${$('review-only').checked ? ' needing review' : ''}.` : 'No sessions need policy review with these settings. This does not prove safety.';
  $('more').hidden = shown >= rows.length;
}
async function run(useSample) {
  if (busy) return;
  busy = true;
  clearResults();
  $('inputs').disabled = true;
  $('clear').disabled = true;
  status('Checking recorded activity…');
  try {
    let text, source;
    if (useSample) {
      text = sample;
      $('activity').value = '';
      $('domains').value = 'docs.example.com';
      source = 'Synthetic sample · invented activity';
    } else {
      const file = $('activity').files[0];
      if (!file) throw new Error('Choose an activity file first, or try the sample review.');
      if (file.size > maxBytes) throw new Error('Choose an activity file of 2 MB or less.');
      try { text = new TextDecoder('utf-8', {fatal:true}).decode(await file.arrayBuffer()); }
      catch { throw new Error('Use a UTF-8 JSONL activity file.'); }
      source = `Your file: ${file.name}`;
    }
    const domains = $('domains').value.split(/\r?\n/).map(s => s.trim()).filter(Boolean);
    const response = await fetch('/api/review', {method:'POST', headers:{'Content-Type':'application/json','X-AgentWatch-Token':token}, body:JSON.stringify({events:text,domains})});
    const result = await response.json();
    if (!response.ok) throw new Error(result.error || 'Review failed. Please try again.');
    report = result.report;
    $('source').textContent = source;
    $('sessions').textContent = report.candidate_sessions;
    $('flagged').textContent = report.sessions.filter(r => r.review).length;
    $('findings').textContent = report.sessions.reduce((n,r) => n+r.findings.length,0);
    $('html-download').href = blobUrl(result.html,'text/html');
    $('json-download').href = blobUrl(JSON.stringify(report,null,2),'application/json');
    $('empty').hidden = true;
    $('results').hidden = false;
    $('review-only').checked = true;
    shown = 20;
    showCards();
    status('Review complete. Findings need human investigation.');
  } catch (error) {
    clearResults();
    status(error instanceof TypeError ? 'Cannot reach AgentWatch. Check that the local server is running, then reload this page.' : error.message,true);
  } finally {
    busy = false;
    $('inputs').disabled = false;
    $('clear').disabled = !report;
  }
}
$('review-form').addEventListener('submit', event => {event.preventDefault(); run(false);});
$('sample').addEventListener('click', () => run(true));
$('clear').addEventListener('click', () => {clearResults(); $('activity').value=''; status('Results cleared. Choose a file to start again.');});
['activity','domains'].forEach(id => $(id).addEventListener('input', () => {if (!busy) {clearResults(); status('Settings changed. Check activity to generate fresh results.');}}));
$('review-only').addEventListener('change', () => {shown=20;showCards();});
$('more').addEventListener('click', () => {shown+=20;showCards();});
$('download-sample').addEventListener('click', () => {
  const url = URL.createObjectURL(new Blob([sample],{type:'application/x-ndjson'}));
  const link = document.createElement('a'); link.href=url; link.download='agentwatch-sample.jsonl'; link.click();
  setTimeout(() => URL.revokeObjectURL(url),1000);
});
