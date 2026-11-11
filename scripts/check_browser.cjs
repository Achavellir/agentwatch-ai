/* Developer-only browser checks. Requires playwright and axe-core on NODE_PATH.
   Usage: AGENTWATCH_URL=http://127.0.0.1:8765 node scripts/check_browser.cjs
   Uses generated, non-confidential files; never reads a user's activity logs. */
const {chromium} = require('playwright');
const axe = require('axe-core');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const path = require('node:path');
(async () => {
  const output = process.env.QA_OUTPUT || '/tmp/agentwatch-browser-results';
  await fs.mkdir(output,{recursive:true});
  const launch = {headless:true};
  if (process.env.CHROME_PATH) launch.executablePath=process.env.CHROME_PATH;
  const browser = await chromium.launch(launch);
  try {
    const context=await browser.newContext({acceptDownloads:true});
    const page=await context.newPage();
    const errors=[]; const requests=[];
    page.on('pageerror',e=>errors.push(e.message));
    page.on('request',r=>requests.push(r.url()));
    await page.goto(process.env.AGENTWATCH_URL || 'http://127.0.0.1:8765');
    const base=new URL(page.url()).origin;
    await page.evaluate(() => {
      window.qaVitals={lcp:null,cls:0};
      new PerformanceObserver(list=>{for(const e of list.getEntries())window.qaVitals.lcp=e.startTime;}).observe({type:'largest-contentful-paint',buffered:true});
      new PerformanceObserver(list=>{for(const e of list.getEntries())if(!e.hadRecentInput)window.qaVitals.cls+=e.value;}).observe({type:'layout-shift',buffered:true});
    });
    await page.getByRole('button',{name:'Check activity',exact:true}).click();
    await page.getByRole('status').filter({hasText:'Choose an activity file first'}).waitFor();
    await page.getByRole('button',{name:'Try a sample review'}).click();
    await page.getByRole('status').filter({hasText:'Review complete'}).waitFor();
    assert.equal(await page.locator('#sessions').textContent(),'3');
    assert.equal(await page.locator('#flagged').textContent(),'2');
    await page.getByText('Show recorded evidence',{exact:true}).first().click();
    await page.getByText('Event sample-write · Input line 3',{exact:true}).waitFor();
    const axeResults=[];
    for (const width of [375,768,1440]) {
      await page.setViewportSize({width,height:1000});
      await page.screenshot({path:path.join(output,`review-${width}.png`),fullPage:true});
      assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),true,`overflow at ${width}`);
      await page.evaluate(axe.source);
      const scan=await page.evaluate(async()=>{const r=await axe.run(document,{runOnly:{type:'tag',values:['wcag2a','wcag2aa','wcag21aa','wcag22aa']}});return r.violations.map(v=>({id:v.id,impact:v.impact,nodes:v.nodes.map(n=>n.target)}));});
      axeResults.push({width,violations:scan});
      assert.deepEqual(scan,[],`Accessibility failures at ${width}`);
    }
    for(const [id,name] of [['html-download','report.html'],['json-download','report.json']]) {
      const pending=page.waitForEvent('download'); await page.locator('#'+id).click();
      const download=await pending; await download.saveAs(path.join(output,name));
    }
    const downloaded=JSON.parse(await fs.readFile(path.join(output,'report.json'),'utf8'));
    assert.equal(downloaded.candidate_sessions,3);
    assert.equal(downloaded.model,null);
    assert.match(await fs.readFile(path.join(output,'report.html'),'utf8'),/ACTION_WITHOUT_APPROVAL/);
    const sampleDownload=page.waitForEvent('download');
    await page.getByRole('button',{name:'Download sample file'}).click();
    assert.equal((await sampleDownload).suggestedFilename(),'agentwatch-sample.jsonl');
    await page.locator('#review-only').uncheck();
    assert.equal(await page.locator('.session').count(),3);
    await page.locator('#domains').fill('changed.example');
    assert.equal(await page.locator('#results').isVisible(),false,'Stale report must disappear');
    const event={event_id:'event-1',session_id:'session-1',tool:'http',destination:'https://docs.example.com',bytes_sent:50,approved:true,sensitive:false};
    const upload=async content=>page.locator('#activity').setInputFiles({name:'generated.jsonl',mimeType:'application/x-ndjson',buffer:Buffer.isBuffer(content)?content:Buffer.from(content)});
    const submit=()=>page.getByRole('button',{name:'Check activity',exact:true}).click();
    await upload(JSON.stringify(event)); await page.locator('#domains').fill('docs.example.com'); await submit();
    await page.getByRole('status').filter({hasText:'Review complete'}).waitFor();
    assert.equal(await page.locator('#flagged').textContent(),'0');
    assert.match(await page.locator('#list-summary').textContent(),/does not prove safety/);
    await page.locator('#domains').fill('');await submit();
    await page.getByRole('status').filter({hasText:'Review complete'}).waitFor();
    assert.equal(await page.locator('#flagged').textContent(),'1');
    await page.locator('#domains').fill('https://bad.example'); await submit();
    await page.getByRole('status').filter({hasText:'exact ASCII hostname'}).waitFor();
    assert.equal(await page.locator('#results').isVisible(),false);
    await page.locator('#domains').fill('docs.example.com');
    for(const [content,message] of [['not JSON','Line 1'],[Buffer.from([255]),'UTF-8'],[' '.repeat(2000001),'2 MB or less'],['','No events']]) {
      await upload(content);await submit(); await page.getByRole('status').filter({hasText:message}).waitFor();
      assert.equal(await page.locator('#results').isVisible(),false);
    }
    const malicious={...event,event_id:'<img src=x onerror=alert(1)>',session_id:'<script>alert(1)</script>',destination:'https://outside.example'};
    await upload(JSON.stringify(malicious));await submit();
    await page.getByRole('status').filter({hasText:'Review complete'}).waitFor();
    assert.equal(await page.locator('#cards script,#cards img').count(),0);
    assert.equal(await page.locator('.session h3').textContent(),malicious.session_id);
    const many=Array.from({length:25},(_,i)=>JSON.stringify({...event,event_id:'event-'+i,session_id:'session-'+i})).join('\n');
    await upload(many);await submit();await page.getByRole('status').filter({hasText:'Review complete'}).waitFor();
    await page.locator('#review-only').uncheck();assert.equal(await page.locator('.session').count(),20);
    await page.getByRole('button',{name:'Show more sessions'}).click();assert.equal(await page.locator('.session').count(),25);
    await page.getByRole('button',{name:'Clear results'}).click();assert.equal(await page.locator('#results').isVisible(),false);
    await page.route('**/api/review',route=>route.abort());
    await page.getByRole('button',{name:'Try a sample review'}).click();
    await page.getByRole('status').filter({hasText:'Cannot reach AgentWatch'}).waitFor();
    await page.unroute('**/api/review');
    await page.reload();
    // Keyboard-only sample action and evidence expansion.
    await page.locator('#sample').focus(); await page.keyboard.press('Enter');
    await page.getByRole('status').filter({hasText:'Review complete'}).waitFor();
    await page.locator('.session summary').first().focus(); await page.keyboard.press('Enter');
    assert.equal(await page.locator('.session details').first().getAttribute('open'),'');
    await page.keyboard.press('Tab');
    const focus=await page.evaluate(()=>document.activeElement.tagName);
    assert.notEqual(focus,'BODY');
    assert.deepEqual(errors,[]);
    assert.ok(requests.every(url=>url.startsWith(base)||url.startsWith('blob:')),'Unexpected external request');
    const vitals=await page.evaluate(()=>({navigation:performance.getEntriesByType('navigation')[0].duration}));
    await fs.writeFile(path.join(output,'results.json'),JSON.stringify({result:'PASS',axeResults,uncaughtErrors:errors,externalRequests:0,checks:['sample','file input','HTML and JSON downloads','sample download','filter','evidence','stale results','invalid domain','invalid JSON','invalid UTF-8','oversized input','empty input','untrusted markup','pagination','clear','network failure','keyboard activation'],vitals,limits:'No prior visual baseline; visual regression inconclusive. No manual screen-reader audit or field INP measurement.'},null,2));
    console.log('Browser interactions, three responsive layouts and axe checks passed. '+output);
  } finally {await browser.close();}
})().catch(e=>{console.error(e);process.exitCode=1;});
